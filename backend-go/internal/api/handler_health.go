package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/health"
	"macflow/internal/netctl"
	"macflow/internal/singbox"
	"macflow/internal/state"
)

// handleHealth runs all health checks and returns detailed results.
//
// GET /api/health
func (s *Server) handleHealth(c *gin.Context) {
	checks, overall, elapsed := s.monitor.CollectChecks()
	s.monitor.ApplyResults(checks, overall)

	_, alerts, _, _ := s.monitor.GetState()

	// Build legacy status fields
	legacyMap := map[string]string{}
	for name, ch := range checks {
		switch ch.Status {
		case "ok":
			switch name {
			case "singbox":
				legacyMap[name] = "running"
			case "tun":
				legacyMap[name] = "up"
			default:
				legacyMap[name] = "loaded"
			}
		default:
			switch name {
			case "singbox":
				legacyMap[name] = "not running"
			case "tun":
				legacyMap[name] = "down"
			default:
				legacyMap[name] = "missing"
			}
		}
	}

	// Active alerts
	var activeAlerts []health.Alert
	for _, a := range alerts {
		if a.Status == "active" {
			activeAlerts = append(activeAlerts, a)
		}
	}
	if activeAlerts == nil {
		activeAlerts = []health.Alert{}
	}

	resp := gin.H{
		"overall_status":    overall,
		"checked_at":        time.Now().Unix(),
		"latency_ms":        elapsed.Milliseconds(),
		"checks":            checks,
		"active_alerts":     activeAlerts,
		"fail_close_active": s.rt.GetFailCloseActive(),
		"fail_close_since":  s.rt.GetFailCloseSince(),
		"fail_close_reason": s.rt.GetFailCloseReason(),
		"version":           s.cfg.Version,
	}
	// Add legacy top-level fields
	for k, v := range legacyMap {
		resp[k] = v
	}

	c.JSON(http.StatusOK, resp)
}

// handleAlerts returns the current list of alerts.
//
// GET /api/alerts
func (s *Server) handleAlerts(c *gin.Context) {
	_, alerts, _, _ := s.monitor.GetState()
	c.JSON(http.StatusOK, alerts)
}

// handleAlertAck acknowledges an alert by ID.
//
// POST /api/alerts/:id/ack
func (s *Server) handleAlertAck(c *gin.Context) {
	alertID := c.Param("id")
	if s.monitor.AckAlert(alertID) {
		s.audit.Log("alert_ack", alertID)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"detail": "alert not found"})
	}
}

// handleCaptiveStatus checks captive portal status for a device.
//
// GET /api/captive/status
func (s *Server) handleCaptiveStatus(c *gin.Context) {
	ip := c.Query("ip")
	mac := c.Query("mac")

	st := s.store.Read()
	macToIP := resolveMACToIPLocal()

	// Resolve IP↔MAC
	if mac == "" && ip != "" {
		for m, mip := range macToIP {
			if mip == ip {
				mac = m
				break
			}
		}
	}
	if ip == "" && mac != "" {
		ip = macToIP[normalizeMac(mac)]
	}

	// Find device
	var deviceName, nodeTag string
	managed := false
	macNorm := normalizeMac(mac)

	for _, d := range st.Devices {
		if normalizeMac(d.MAC) == macNorm {
			managed = d.Managed
			deviceName = d.Name
			nodeTag = d.NodeTag
			break
		}
	}

	serviceEnabled := st.Enabled
	internetAllowed := !serviceEnabled || managed

	var reason, message string
	if !serviceEnabled {
		reason = "service-disabled"
		message = "分流服务未启用，所有设备正常联网。"
	} else if managed {
		reason = "managed"
		message = "设备已纳入策略管理,请等待 1-3 秒后重试联网。"
	} else {
		reason = "unmanaged"
		message = "设备未纳入管理，网络访问可能受到限制。请联系管理员。"
	}

	panelURL := ""
	if s.cfg != nil {
		panelURL = "http://" + c.Request.Host
	}

	c.JSON(http.StatusOK, gin.H{
		"ip":              ip,
		"mac":             mac,
		"device_name":     deviceName,
		"node_tag":        nodeTag,
		"managed":         managed,
		"service_enabled": serviceEnabled,
		"internet_allowed": internetAllowed,
		"reason":          reason,
		"message":         message,
		"panel_url":       panelURL,
		"updated_at":      time.Now().Unix(),
	})
}

// handleNodesHealthRefresh probes all enabled nodes' latency via Clash API.
//
// POST /api/nodes/health/refresh
func (s *Server) handleNodesHealthRefresh(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if v, err := parseInt(l); err == nil && v >= 1 && v <= 200 {
			limit = v
		}
	}

	st := s.store.Read()

	// Collect enabled nodes with valid servers
	type probeTarget struct {
		tag string
		idx int // index in st.Nodes
	}
	var targets []probeTarget
	for i, n := range st.Nodes {
		if !n.Enabled || n.Tag == "" {
			continue
		}
		if n.Server == "" || n.Server == "127.0.0.1" || n.Server == "0.0.0.0" {
			continue
		}
		targets = append(targets, probeTarget{tag: n.Tag, idx: i})
	}

	// Limit
	if len(targets) > limit {
		targets = targets[:limit]
	}
	if len(targets) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"ok": true, "checked": 0, "healthy": 0, "unhealthy": 0,
		})
		return
	}

	// Parallel probe via Clash API
	type probeResult struct {
		tag     string
		latency int
		ok      bool
	}
	ch := make(chan probeResult, len(targets))
	for _, t := range targets {
		go func(tag string) {
			lat := proxyDelayMs(tag, 2500)
			ch <- probeResult{tag: tag, latency: lat, ok: lat > 0}
		}(t.tag)
	}

	results := make([]probeResult, 0, len(targets))
	for i := 0; i < len(targets); i++ {
		results = append(results, <-ch)
	}

	// Update state
	healthy, unhealthy := 0, 0
	s.store.Update(func(st *state.State) {
		for _, r := range results {
			for j := range st.Nodes {
				if st.Nodes[j].Tag == r.tag {
					if r.ok {
						st.Nodes[j].Latency = &r.latency
						st.Nodes[j].HealthFails = 0
						healthy++
					} else {
						neg := -1
						st.Nodes[j].Latency = &neg
						st.Nodes[j].HealthFails++
						unhealthy++
					}
					score, status := health.ComputeNodeHealthScore(
						st.Nodes[j].Latency, st.Nodes[j].SpeedMbps,
						st.Nodes[j].HealthFails, st.Nodes[j].Enabled,
					)
					st.Nodes[j].HealthScore = score
					st.Nodes[j].HealthStatus = status
					break
				}
			}
		}
	})

	// Hot-apply if service enabled
	var runtime gin.H
	if s.store.Read().Enabled {
		r := s.rt.HotApply(false)
		runtime = gin.H{
			"singbox": r.Singbox, "nftables": r.Nftables, "ip_rules": r.IPRules,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":        true,
		"checked":   len(results),
		"healthy":   healthy,
		"unhealthy": unhealthy,
		"runtime":   runtime,
	})
}

// resolveMACToIPLocal reads ARP/DHCP to build MAC→IP mapping.
func resolveMACToIPLocal() map[string]string {
	return netctl.ResolveMACToIP()
}

// parseInt is a small helper.
func parseInt(s string) (int, error) {
	var v int
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}

// proxyDelayMs tests node latency via Clash API.
func proxyDelayMs(tag string, timeoutMs int) int {
	return singbox.ProxyDelayMs(tag, timeoutMs)
}
