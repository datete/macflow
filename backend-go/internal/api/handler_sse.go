package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/singbox"
)

// SSE subsystem
var (
	sseClients    []chan string
	sseClientsMu  sync.Mutex
	sseMaxClients = 50
)

// handleSSE provides Server-Sent Events stream.
//
// GET /api/events
func (s *Server) handleSSE(c *gin.Context) {
	// Independent auth check for SSE (supports token as query param)
	authCfg := s.auth.LoadAuth()
	if authCfg.AuthEnabled {
		token := c.Query("token")
		if token == "" {
			token = c.GetHeader("X-Auth-Token")
		}
		if token == "" {
			token, _ = c.Cookie("macflow_token")
		}
		if !s.auth.ValidateSession(token) {
			c.JSON(http.StatusUnauthorized, gin.H{"detail": "认证失败"})
			return
		}
	}

	sseClientsMu.Lock()
	if len(sseClients) >= sseMaxClients {
		sseClientsMu.Unlock()
		c.JSON(http.StatusServiceUnavailable, gin.H{"detail": "SSE 连接数已满"})
		return
	}

	ch := make(chan string, 50)
	sseClients = append(sseClients, ch)
	sseClientsMu.Unlock()

	// Remove client on disconnect
	defer func() {
		sseClientsMu.Lock()
		for i, cl := range sseClients {
			if cl == ch {
				sseClients = append(sseClients[:i], sseClients[i+1:]...)
				break
			}
		}
		sseClientsMu.Unlock()
		close(ch)
	}()

	// SSE Headers
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	// Send connected event
	fmt.Fprintf(c.Writer, "event: connected\ndata: {}\n\n")
	c.Writer.Flush()

	ctx := c.Request.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprint(c.Writer, msg)
			c.Writer.Flush()
		case <-time.After(30 * time.Second):
			// Keepalive
			fmt.Fprint(c.Writer, ": keepalive\n\n")
			c.Writer.Flush()
		}
	}
}

// sseBroadcast sends an SSE event to all connected clients.
func sseBroadcast(eventType string, data interface{}) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return
	}
	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, string(jsonBytes))

	sseClientsMu.Lock()
	defer sseClientsMu.Unlock()

	for _, ch := range sseClients {
		select {
		case ch <- msg:
		default:
			// Drop if channel full
		}
	}
}

// StartSSELoops starts the background SSE push loops.
// Called from NewRouter during initialization.
func startSSELoops(s *Server) {
	go sseTrafficLoop(context.Background(), s)
	go sseSysInfoLoop(context.Background(), s)
}

func sseTrafficLoop(ctx context.Context, s *Server) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sseClientsMu.Lock()
			clientCount := len(sseClients)
			sseClientsMu.Unlock()
			if clientCount == 0 {
				continue
			}

			// Traffic
			if data, err := singbox.GetTraffic(); err == nil {
				up, _ := data["up"].(float64)
				down, _ := data["down"].(float64)
				sseBroadcast("traffic", map[string]interface{}{
					"up_bytes":  int64(up),
					"down_bytes": int64(down),
					"up_str":    fmtBytes(int64(up)) + "/s",
					"down_str":  fmtBytes(int64(down)) + "/s",
					"ts":        time.Now().Unix(),
				})
			}

			// Connections
			if data, err := singbox.GetConnections(); err == nil {
				conns, _ := data["connections"].([]interface{})
				upTotal, _ := data["uploadTotal"].(float64)
				downTotal, _ := data["downloadTotal"].(float64)
				sseBroadcast("connections", map[string]interface{}{
					"count":          len(conns),
					"upload_total":   int64(upTotal),
					"download_total": int64(downTotal),
				})
			}

			// Status snapshot
			st := s.store.Read()
			enabledNodes := 0
			managedDevices := 0
			for _, n := range st.Nodes {
				if n.Enabled {
					enabledNodes++
				}
			}
			for _, d := range st.Devices {
				if d.Managed {
					managedDevices++
				}
			}
			_, alerts, overall, _ := s.monitor.GetState()
			activeAlertCount := 0
			for _, a := range alerts {
				if a.Status == "active" {
					activeAlertCount++
				}
			}
			sseBroadcast("status", map[string]interface{}{
				"enabled":            st.Enabled,
				"node_count":         len(st.Nodes),
				"node_enabled":       enabledNodes,
				"device_count":       len(st.Devices),
				"managed_count":      managedDevices,
				"policy_version":     st.PolicyVersion,
				"rollback_version":   st.RollbackVersion,
				"last_apply":         st.LastApply,
				"overall_health":     overall,
				"active_alert_count": activeAlertCount,
				"fail_close_active":  s.rt.GetFailCloseActive(),
			})
		}
	}
}

func sseSysInfoLoop(ctx context.Context, s *Server) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sseClientsMu.Lock()
			clientCount := len(sseClients)
			sseClientsMu.Unlock()
			if clientCount == 0 {
				continue
			}

			uptimeSec := int(time.Since(bootTime).Seconds())
			h := uptimeSec / 3600
			m := (uptimeSec % 3600) / 60
			sec := uptimeSec % 60

			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			memMB := float64(mem.Alloc) / (1024 * 1024)

			sseBroadcast("sysinfo", map[string]interface{}{
				"uptime_sec": uptimeSec,
				"uptime_str": fmt.Sprintf("%dh %dm %ds", h, m, sec),
				"memory_mb":  fmt.Sprintf("%.1f", memMB),
				"pid":        os.Getpid(),
			})
		}
	}
}
