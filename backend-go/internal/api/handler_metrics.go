package api

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// handleMetrics exposes Prometheus-compatible metrics.
//
// GET /api/metrics
// Returns plain-text in Prometheus exposition format.
func (s *Server) handleMetrics(c *gin.Context) {
	st := s.store.Read()
	checks, alerts, overall, _ := s.monitor.GetState()

	// Count stats
	enabledNodes, offlineNodes := 0, 0
	for _, n := range st.Nodes {
		if n.Enabled {
			enabledNodes++
		}
		if n.HealthStatus == "offline" || n.HealthStatus == "down" || n.HealthStatus == "error" {
			offlineNodes++
		}
	}
	managedDevices := 0
	for _, d := range st.Devices {
		if d.Managed {
			managedDevices++
		}
	}
	activeAlerts, criticalAlerts := 0, 0
	for _, a := range alerts {
		if a.Status == "active" {
			activeAlerts++
			if a.Severity == "critical" {
				criticalAlerts++
			}
		}
	}

	// Health check statuses
	healthOK, healthWarn, healthCritical := 0, 0, 0
	for _, cr := range checks {
		switch cr.Status {
		case "ok":
			healthOK++
		case "warn":
			healthWarn++
		case "critical":
			healthCritical++
		}
	}

	overallVal := 0
	if overall == "ok" {
		overallVal = 1
	} else if overall == "warn" {
		overallVal = 2
	} else if overall == "critical" {
		overallVal = 3
	}

	uptimeSec := time.Since(bootTime).Seconds()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var sb strings.Builder

	writeLine := func(name, help, typ string) {
		fmt.Fprintf(&sb, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	writeGauge := func(name string, labels map[string]string, val interface{}) {
		if len(labels) == 0 {
			fmt.Fprintf(&sb, "%s %v\n", name, val)
		} else {
			var ls []string
			for k, v := range labels {
				ls = append(ls, fmt.Sprintf(`%s="%s"`, k, v))
			}
			fmt.Fprintf(&sb, "%s{%s} %v\n", name, strings.Join(ls, ","), val)
		}
	}

	// macflow_up
	writeLine("macflow_up", "1 if macflow service is running", "gauge")
	writeGauge("macflow_up", nil, 1)

	// macflow_uptime_seconds
	writeLine("macflow_uptime_seconds", "Seconds since macflow started", "gauge")
	writeGauge("macflow_uptime_seconds", nil, fmt.Sprintf("%.0f", uptimeSec))

	// macflow_service_enabled
	enabled := 0
	if st.Enabled {
		enabled = 1
	}
	writeLine("macflow_service_enabled", "1 if traffic routing is enabled", "gauge")
	writeGauge("macflow_service_enabled", nil, enabled)

	// macflow_nodes_total
	writeLine("macflow_nodes_total", "Total number of configured nodes", "gauge")
	writeGauge("macflow_nodes_total", nil, len(st.Nodes))

	// macflow_nodes_enabled
	writeLine("macflow_nodes_enabled", "Number of enabled nodes", "gauge")
	writeGauge("macflow_nodes_enabled", nil, enabledNodes)

	// macflow_nodes_offline
	writeLine("macflow_nodes_offline", "Number of nodes currently offline/error", "gauge")
	writeGauge("macflow_nodes_offline", nil, offlineNodes)

	// macflow_devices_total
	writeLine("macflow_devices_total", "Total number of tracked devices", "gauge")
	writeGauge("macflow_devices_total", nil, len(st.Devices))

	// macflow_devices_managed
	writeLine("macflow_devices_managed", "Number of managed devices", "gauge")
	writeGauge("macflow_devices_managed", nil, managedDevices)

	// macflow_alerts_active
	writeLine("macflow_alerts_active", "Number of active alerts", "gauge")
	writeGauge("macflow_alerts_active", nil, activeAlerts)

	// macflow_alerts_critical
	writeLine("macflow_alerts_critical", "Number of active critical alerts", "gauge")
	writeGauge("macflow_alerts_critical", nil, criticalAlerts)

	// macflow_health_overall
	writeLine("macflow_health_overall", "Overall health status: 1=ok, 2=warn, 3=critical, 0=unknown", "gauge")
	writeGauge("macflow_health_overall", nil, overallVal)

	// macflow_health_checks
	writeLine("macflow_health_checks_total", "Number of health checks by status", "gauge")
	writeGauge("macflow_health_checks_total", map[string]string{"status": "ok"}, healthOK)
	writeGauge("macflow_health_checks_total", map[string]string{"status": "warn"}, healthWarn)
	writeGauge("macflow_health_checks_total", map[string]string{"status": "critical"}, healthCritical)

	// macflow_fail_close_active
	failClose := 0
	if s.rt.GetFailCloseActive() {
		failClose = 1
	}
	writeLine("macflow_fail_close_active", "1 if fail-close guard is active", "gauge")
	writeGauge("macflow_fail_close_active", nil, failClose)

	// Go runtime memory
	writeLine("macflow_go_alloc_bytes", "Go heap bytes in use", "gauge")
	writeGauge("macflow_go_alloc_bytes", nil, mem.Alloc)

	writeLine("macflow_go_goroutines", "Number of running goroutines", "gauge")
	writeGauge("macflow_go_goroutines", nil, runtime.NumGoroutine())

	// Per-node latency
	writeLine("macflow_node_latency_ms", "Last probe latency of each node (ms), -1 if unknown", "gauge")
	for _, n := range st.Nodes {
		latency := -1
		if n.Latency != nil {
			latency = *n.Latency
		}
		writeGauge("macflow_node_latency_ms", map[string]string{
			"tag":    n.Tag,
			"server": n.Server,
		}, latency)
	}

	// Per-node health status (1=ok, 0=offline/error, -1=untested)
	writeLine("macflow_node_health", "Node health: 1=ok/unknown, 0=offline/error", "gauge")
	for _, n := range st.Nodes {
		val := 1
		if n.HealthStatus == "offline" || n.HealthStatus == "down" || n.HealthStatus == "error" {
			val = 0
		} else if n.HealthStatus == "" {
			val = -1
		}
		writeGauge("macflow_node_health", map[string]string{
			"tag": n.Tag,
		}, val)
	}

	// SSE client count
	sseClientsMu.Lock()
	sseCount := len(sseClients)
	sseClientsMu.Unlock()
	writeLine("macflow_sse_clients", "Number of active SSE connections", "gauge")
	writeGauge("macflow_sse_clients", nil, sseCount)

	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.String(http.StatusOK, sb.String())
}
