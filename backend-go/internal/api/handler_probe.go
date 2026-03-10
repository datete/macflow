package api

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/health"
	"macflow/internal/singbox"
	"macflow/internal/state"
)

// handleNodeTest tests a node's latency via Clash API with TCP fallback.
//
// POST /api/nodes/:tag/test
func (s *Server) handleNodeTest(c *gin.Context) {
	tag := c.Param("tag")
	st := s.store.Read()

	var node *state.Node
	for i := range st.Nodes {
		if st.Nodes[i].Tag == tag {
			node = &st.Nodes[i]
			break
		}
	}
	if node == nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "节点不存在"})
		return
	}

	// Check for invalid server
	if node.Server == "" || node.Server == "127.0.0.1" || node.Server == "0.0.0.0" {
		neg := -1
		s.store.Update(func(st *state.State) {
			for j := range st.Nodes {
				if st.Nodes[j].Tag == tag {
					st.Nodes[j].Latency = &neg
					st.Nodes[j].HealthFails++
					score, status := health.ComputeNodeHealthScore(
						st.Nodes[j].Latency, st.Nodes[j].SpeedMbps,
						st.Nodes[j].HealthFails, st.Nodes[j].Enabled,
					)
					st.Nodes[j].HealthScore = score
					st.Nodes[j].HealthStatus = status
					break
				}
			}
		})
		c.JSON(http.StatusOK, gin.H{
			"ok": false, "tag": tag, "latency": -1,
			"health_score": 0, "health_status": "unhealthy",
		})
		return
	}

	// Try Clash API first
	latency := singbox.ProxyDelayMs(tag, 5000)

	// Fallback to TCP connect if Clash API fails
	if latency < 0 {
		t0 := time.Now()
		addr := net.JoinHostPort(node.Server, fmt.Sprintf("%d", node.ServerPort))
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			conn.Close()
			latency = int(time.Since(t0).Milliseconds())
		}
	}

	ok := latency > 0

	// Update state
	var finalScore int
	var finalStatus string
	s.store.Update(func(st *state.State) {
		for j := range st.Nodes {
			if st.Nodes[j].Tag == tag {
				if ok {
					st.Nodes[j].Latency = &latency
					st.Nodes[j].HealthFails = 0
				} else {
					neg := -1
					st.Nodes[j].Latency = &neg
					st.Nodes[j].HealthFails++
				}
				finalScore, finalStatus = health.ComputeNodeHealthScore(
					st.Nodes[j].Latency, st.Nodes[j].SpeedMbps,
					st.Nodes[j].HealthFails, st.Nodes[j].Enabled,
				)
				st.Nodes[j].HealthScore = finalScore
				st.Nodes[j].HealthStatus = finalStatus
				break
			}
		}
	})

	c.JSON(http.StatusOK, gin.H{
		"ok":            ok,
		"tag":           tag,
		"latency":       latency,
		"health_score":  finalScore,
		"health_status": finalStatus,
	})
}

// handleNodeSpeedtest tests a node's download speed via Clash proxy.
//
// POST /api/nodes/:tag/speedtest
func (s *Server) handleNodeSpeedtest(c *gin.Context) {
	tag := c.Param("tag")
	st := s.store.Read()

	var node *state.Node
	for i := range st.Nodes {
		if st.Nodes[i].Tag == tag {
			node = &st.Nodes[i]
			break
		}
	}
	if node == nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "节点不存在"})
		return
	}

	if node.Server == "" || node.Server == "127.0.0.1" || node.Server == "0.0.0.0" {
		c.JSON(http.StatusOK, gin.H{
			"ok": false, "tag": tag, "latency_ms": -1, "speed_mbps": 0,
			"message": "invalid node server",
		})
		return
	}

	// Test latency first
	latency := singbox.ProxyDelayMs(tag, 5000)
	if latency < 0 {
		t0 := time.Now()
		addr := net.JoinHostPort(node.Server, fmt.Sprintf("%d", node.ServerPort))
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			conn.Close()
			latency = int(time.Since(t0).Milliseconds())
		}
	}

	// Speed test via selector
	speedMbps := measureSpeedViaSelector(tag)

	ok := latency > 0

	// Update state
	var finalScore int
	var finalStatus string
	s.store.Update(func(st *state.State) {
		for j := range st.Nodes {
			if st.Nodes[j].Tag == tag {
				if ok {
					st.Nodes[j].Latency = &latency
					st.Nodes[j].HealthFails = 0
				} else {
					neg := -1
					st.Nodes[j].Latency = &neg
					st.Nodes[j].HealthFails++
				}
				if speedMbps > 0 {
					st.Nodes[j].SpeedMbps = speedMbps
				}
				finalScore, finalStatus = health.ComputeNodeHealthScore(
					st.Nodes[j].Latency, st.Nodes[j].SpeedMbps,
					st.Nodes[j].HealthFails, st.Nodes[j].Enabled,
				)
				st.Nodes[j].HealthScore = finalScore
				st.Nodes[j].HealthStatus = finalStatus
				break
			}
		}
	})

	message := "ok"
	if !ok {
		message = "latency test failed"
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            ok,
		"tag":           tag,
		"latency_ms":    latency,
		"speed_mbps":    speedMbps,
		"health_score":  finalScore,
		"health_status": finalStatus,
		"message":       message,
	})
}

// measureSpeedViaSelector switches selector, downloads, measures speed, restores.
func measureSpeedViaSelector(tag string) float64 {
	egressLock.Lock()
	defer egressLock.Unlock()

	// Save current selector
	origTag := ""
	if now, _, err := singbox.GetSelectorState(); err == nil {
		origTag = now
	}

	// Switch
	if tag != origTag {
		singbox.SetSelector(tag)
		time.Sleep(250 * time.Millisecond)
	}
	defer func() {
		if origTag != "" && origTag != tag {
			singbox.SetSelector(origTag)
		}
	}()

	// Try download URLs
	downloadURLs := []string{
		"https://speed.cloudflare.com/__down?bytes=6000000",
		"https://cachefly.cachefly.net/5mb.test",
		"https://proof.ovh.net/files/1Mb.dat",
	}

	proxyURL, _ := url.Parse("http://127.0.0.1:1080")
	client := &http.Client{
		Timeout:   6 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	for _, dlURL := range downloadURLs {
		resp, err := client.Get(dlURL)
		if err != nil {
			continue
		}

		t0 := time.Now()
		buf := make([]byte, 32768)
		totalBytes := 0
		maxBytes := 3 * 1024 * 1024 // 3MB
		maxTime := 5 * time.Second

		for {
			if time.Since(t0) > maxTime || totalBytes >= maxBytes {
				break
			}
			n, err := resp.Body.Read(buf)
			totalBytes += n
			if err == io.EOF || err != nil {
				break
			}
		}
		resp.Body.Close()

		elapsed := time.Since(t0).Seconds()
		if totalBytes < 256*1024 || elapsed < 0.1 {
			continue
		}

		mbps := float64(totalBytes*8) / (elapsed * 1_000_000)
		return mbps
	}

	return 0
}
