// Package health implements system health checks, node probing,
// fail-close guard logic, and alert management.
//
// Key improvements over Python version:
// - Health checks run concurrently via goroutines (native, no ThreadPoolExecutor)
// - Direct netlink/procfs access instead of subprocess calls where possible
// - Probe loop uses context for graceful cancellation
package health

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"macflow/internal/config"
	"macflow/internal/state"
)

// CheckResult represents the result of a single health check.
type CheckResult struct {
	Status    string                 `json:"status"` // ok, warn, critical
	Message   string                 `json:"message"`
	LatencyMs int                    `json:"latency_ms"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Alert represents a health alert.
type Alert struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // warning, critical
	Title       string `json:"title"`
	Message     string `json:"message"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
	Status      string `json:"status"` // active, resolved, acknowledged
	RecoveredAt *int64 `json:"recovered_at,omitempty"`
}

// Monitor manages health state, probes, and fail-close logic.
type Monitor struct {
	mu sync.RWMutex

	Checks        map[string]CheckResult `json:"checks"`
	Alerts        []Alert                `json:"alerts"`
	OverallStatus string                 `json:"overall_status"`
	CheckedAt     int64                  `json:"checked_at"`
	ProbeCycle    int                    `json:"probe_cycle"`

	// Fail-close guard
	FailCloseActive bool   `json:"fail_close_active"`
	FailCloseSince  int64  `json:"fail_close_since"`
	FailCloseReason string `json:"fail_close_reason"`
}

// NewMonitor creates a new health monitor with default state.
func NewMonitor() *Monitor {
	return &Monitor{
		Checks:        make(map[string]CheckResult),
		Alerts:        []Alert{},
		OverallStatus: "unknown",
	}
}

// GetState returns a snapshot of the current health state.
func (m *Monitor) GetState() (map[string]CheckResult, []Alert, string, int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	checks := make(map[string]CheckResult, len(m.Checks))
	for k, v := range m.Checks {
		checks[k] = v
	}
	alerts := make([]Alert, len(m.Alerts))
	copy(alerts, m.Alerts)

	return checks, alerts, m.OverallStatus, m.CheckedAt
}

// AckAlert acknowledges an alert by ID. Returns true if found.
func (m *Monitor) AckAlert(alertID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.Alerts {
		if m.Alerts[i].ID == alertID {
			m.Alerts[i].Status = "acknowledged"
			return true
		}
	}
	return false
}

// GetProbeCycle returns the current probe cycle count.
func (m *Monitor) GetProbeCycle() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ProbeCycle
}

// CollectChecks runs all health checks concurrently and returns results.
func (m *Monitor) CollectChecks() (map[string]CheckResult, string, time.Duration) {
	t0 := time.Now()

	type namedResult struct {
		name   string
		result CheckResult
	}

	checkFns := map[string]func() CheckResult{
		"singbox":    checkSingbox,
		"tun":        checkTUN,
		"nftables":   checkNftables,
		"dns_guard":  checkDNSGuard,
		"leak_guard": checkLeakGuard,
		"ipv6_guard": checkIPv6Guard,
	}

	ch := make(chan namedResult, len(checkFns))
	for name, fn := range checkFns {
		go func(n string, f func() CheckResult) {
			ch <- namedResult{name: n, result: f()}
		}(name, fn)
	}

	checks := make(map[string]CheckResult, len(checkFns))
	for i := 0; i < len(checkFns); i++ {
		nr := <-ch
		checks[nr.name] = nr.result
	}

	overall := computeOverall(checks)
	return checks, overall, time.Since(t0)
}

// ApplyResults updates the monitor's state with new check results.
func (m *Monitor) ApplyResults(checks map[string]CheckResult, overall string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().Unix()
	m.Checks = checks
	m.OverallStatus = overall
	m.CheckedAt = now
	m.ProbeCycle++
}

// RuntimeApplier is an interface for triggering runtime re-apply and fail-close.
// Implemented by runtime.Manager — decoupled for testability.
type RuntimeApplier interface {
	// TriggerApply re-applies nft + singbox + ip rules. The bool result is ignored.
	TriggerApply()
	SetFailClose(active bool, reason string)
	IsFailCloseActive() bool
}

// RunProbeLoop runs the periodic probe loop. Blocked until ctx is cancelled.
// It performs health checks, fail-close guard logic, device IP refresh, and auto-heal.
func (m *Monitor) RunProbeLoop(ctx context.Context, store *state.Store, cfg *config.Config) {
	m.RunProbeLoopWithRT(ctx, store, cfg, nil)
}

// RunProbeLoopWithRT is like RunProbeLoop but accepts an optional RuntimeApplier
// for fail-close and auto-heal integration.
func (m *Monitor) RunProbeLoopWithRT(ctx context.Context, store *state.Store, cfg *config.Config, rt RuntimeApplier) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Track consecutive critical cycles for fail-close activation
	consecutiveCritical := 0
	const failCloseThreshold = 2 // activate after 2 consecutive critical cycles

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checks, overall, _ := m.CollectChecks()
			m.ApplyResults(checks, overall)

			st := store.Read()
			if !st.Enabled {
				continue
			}

			// ── Fail-close guard logic ──
			if rt != nil && st.FailurePolicy == "fail-close" {
				singboxDown := checks["singbox"].Status == "critical"
				tunDown := checks["tun"].Status == "critical"

				if singboxDown || tunDown {
					consecutiveCritical++
					if consecutiveCritical >= failCloseThreshold && !rt.IsFailCloseActive() {
						reason := buildFailCloseReason(checks)
						rt.SetFailClose(true, reason)
						rt.TriggerApply() // re-render nft rules with fail-close active
						m.addAlert("fail-close-activated", "critical",
							"Fail-close 已激活", reason)
						log.Printf("[probe] fail-close activated: %s", reason)
					}
				} else {
					// Services recovered
					if consecutiveCritical > 0 {
						consecutiveCritical = 0
					}
					if rt.IsFailCloseActive() {
						rt.SetFailClose(false, "")
						rt.TriggerApply() // re-render nft without fail-close
						m.resolveAlert("fail-close-activated")
						log.Printf("[probe] fail-close deactivated — services recovered")
					}
				}
			}

			// ── Auto-heal selector ──
			if rt != nil {
				m.autoHealSelector(store, checks)
			}

			// ── Refresh device IP cache ──
			refreshDeviceIPs(store)
		}
	}
}

// buildFailCloseReason constructs a human-readable reason from critical checks.
func buildFailCloseReason(checks map[string]CheckResult) string {
	var parts []string
	for name, c := range checks {
		if c.Status == "critical" {
			parts = append(parts, fmt.Sprintf("%s: %s", name, c.Message))
		}
	}
	if len(parts) == 0 {
		return "unknown critical failure"
	}
	return strings.Join(parts, "; ")
}

// autoHealSelector finds devices whose bound node is unhealthy or disabled
// and switches them to the best available healthy node.
func (m *Monitor) autoHealSelector(store *state.Store, checks map[string]CheckResult) {
	// Only auto-heal if singbox is running (otherwise switching is pointless)
	if checks["singbox"].Status == "critical" {
		return
	}

	st := store.Read()

	// Build node lookup
	nodeMap := make(map[string]*state.Node, len(st.Nodes))
	for i := range st.Nodes {
		nodeMap[st.Nodes[i].Tag] = &st.Nodes[i]
	}

	// Find the best healthy node
	bestTag := ""
	bestScore := -1
	for _, n := range st.Nodes {
		if n.Enabled && n.HealthScore > bestScore && n.HealthStatus == "healthy" {
			bestScore = n.HealthScore
			bestTag = n.Tag
		}
	}
	if bestTag == "" {
		return // no healthy node available
	}

	// Check each device's bound node
	var healed []string
	store.Update(func(st *state.State) {
		for i := range st.Devices {
			d := &st.Devices[i]
			if !d.Managed || d.NodeTag == "" || d.NodeTag == bestTag {
				continue
			}
			boundNode, exists := nodeMap[d.NodeTag]
			if !exists {
				continue
			}
			// Only heal if the bound node is truly unhealthy
			if !boundNode.Enabled || boundNode.HealthStatus == "unhealthy" {
				oldTag := d.NodeTag
				d.NodeTag = bestTag
				healed = append(healed, fmt.Sprintf("%s: %s→%s", d.MAC, oldTag, bestTag))
			}
		}
	})

	if len(healed) > 0 {
		msg := fmt.Sprintf("auto-heal: %d devices switched to %s", len(healed), bestTag)
		log.Printf("[probe] %s", msg)
		m.addAlert("auto-heal", "warning", "Auto-heal 节点切换", msg)
	}
}

// refreshDeviceIPs updates device last_ip from ARP/DHCP tables.
func refreshDeviceIPs(store *state.Store) {
	macToIP := make(map[string]string)
	// Read /proc/net/arp
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				mac := strings.ToUpper(fields[3])
				if mac != "00:00:00:00:00:00" {
					macToIP[mac] = fields[0]
				}
			}
		}
	}
	// Read DHCP leases
	for _, f := range []string{"/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases"} {
		if data, err := os.ReadFile(f); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					macToIP[strings.ToUpper(fields[1])] = fields[2]
				}
			}
		}
	}

	if len(macToIP) == 0 {
		return
	}

	store.Update(func(st *state.State) {
		for i := range st.Devices {
			if ip, ok := macToIP[strings.ToUpper(st.Devices[i].MAC)]; ok {
				st.Devices[i].LastIP = ip
			}
		}
	})
}

// addAlert adds or updates an alert.
func (m *Monitor) addAlert(id, severity, title, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().Unix()
	for i := range m.Alerts {
		if m.Alerts[i].ID == id {
			m.Alerts[i].LastSeen = now
			m.Alerts[i].Message = message
			m.Alerts[i].Status = "active"
			m.Alerts[i].RecoveredAt = nil
			return
		}
	}
	m.Alerts = append(m.Alerts, Alert{
		ID:        id,
		Severity:  severity,
		Title:     title,
		Message:   message,
		FirstSeen: now,
		LastSeen:  now,
		Status:    "active",
	})
}

// resolveAlert marks an alert as resolved.
func (m *Monitor) resolveAlert(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().Unix()
	for i := range m.Alerts {
		if m.Alerts[i].ID == id && m.Alerts[i].Status == "active" {
			m.Alerts[i].Status = "resolved"
			m.Alerts[i].RecoveredAt = &now
			return
		}
	}
}

// ── Individual health checks ──
// These run system commands (will be replaced with direct netlink/procfs in phase 2)

func runCmd(name string, args ...string) (int, string, int) {
	t0 := time.Now()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	ms := int(time.Since(t0).Milliseconds())
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), string(out), ms
		}
		return -1, err.Error(), ms
	}
	return 0, string(out), ms
}

func checkSingbox() CheckResult {
	rc, _, ms := runCmd("pidof", "sing-box")
	if rc == 0 {
		return CheckResult{Status: "ok", Message: "sing-box process active", LatencyMs: ms}
	}
	return CheckResult{Status: "critical", Message: "sing-box not running", LatencyMs: ms}
}

func checkTUN() CheckResult {
	rc, out, ms := runCmd("ip", "link", "show", "singtun0")
	up := rc == 0 && strings.Contains(out, "UP")
	if up {
		return CheckResult{Status: "ok", Message: "TUN interface UP", LatencyMs: ms}
	}
	return CheckResult{Status: "critical", Message: "TUN interface down or missing", LatencyMs: ms}
}

func checkNftables() CheckResult {
	rc, _, ms := runCmd("nft", "list", "table", "inet", "macflow")
	if rc == 0 {
		return CheckResult{Status: "ok", Message: "macflow table loaded", LatencyMs: ms}
	}
	return CheckResult{Status: "critical", Message: "macflow table not found", LatencyMs: ms}
}

func checkDNSGuard() CheckResult {
	rc, out, ms := runCmd("nft", "list", "chain", "inet", "macflow", "dns_guard")
	if rc != 0 {
		return CheckResult{
			Status: "critical", Message: "dns_guard chain not found", LatencyMs: ms,
			Details: map[string]interface{}{"chain_exists": false},
		}
	}
	hasUDP := strings.Contains(out, "udp dport 53") && strings.Contains(out, "redirect")
	hasTCP := strings.Contains(out, "tcp dport 53") && strings.Contains(out, "redirect")
	if hasUDP && hasTCP {
		return CheckResult{Status: "ok", Message: "dns_guard active", LatencyMs: ms}
	}
	return CheckResult{Status: "warn", Message: "dns_guard partial redirect rules", LatencyMs: ms}
}

func checkLeakGuard() CheckResult {
	rc, out, ms := runCmd("nft", "list", "chain", "inet", "macflow", "forward_guard")
	if rc != 0 {
		return CheckResult{
			Status: "critical", Message: "leak_guard chain not found", LatencyMs: ms,
			Details: map[string]interface{}{"chain_exists": false},
		}
	}
	checks := map[string]bool{
		"doh_443":     strings.Contains(out, "dport 443") && strings.Contains(out, "drop"),
		"dot_853":     strings.Contains(out, "dport 853") && strings.Contains(out, "drop"),
		"doq_8853":    strings.Contains(out, "dport 8853") && strings.Contains(out, "drop"),
		"stun_3478":   strings.Contains(out, "dport 3478") && strings.Contains(out, "drop"),
	}
	allOK := true
	for _, v := range checks {
		if !v {
			allOK = false
			break
		}
	}
	if allOK {
		return CheckResult{Status: "ok", Message: "leak_guard rules complete", LatencyMs: ms}
	}
	return CheckResult{Status: "warn", Message: "leak_guard missing some blocking rules", LatencyMs: ms}
}

func checkIPv6Guard() CheckResult {
	rc, out, ms := runCmd("nft", "list", "chain", "inet", "macflow", "ipv6_guard")
	if rc != 0 {
		return CheckResult{Status: "warn", Message: "ipv6_guard chain not found (optional)", LatencyMs: ms}
	}
	hasDrop := strings.Contains(out, "ip6") && strings.Contains(out, "drop")
	if hasDrop {
		return CheckResult{Status: "ok", Message: "ipv6_guard active", LatencyMs: ms}
	}
	return CheckResult{Status: "warn", Message: "ipv6_guard no drop rules", LatencyMs: ms}
}

func computeOverall(checks map[string]CheckResult) string {
	hasCritical := false
	hasWarn := false
	allOK := true
	for _, c := range checks {
		switch c.Status {
		case "critical":
			hasCritical = true
			allOK = false
		case "warn":
			hasWarn = true
			allOK = false
		default:
			if c.Status != "ok" {
				allOK = false
			}
		}
	}
	if hasCritical {
		return "critical"
	}
	if hasWarn {
		return "warn"
	}
	if allOK {
		return "ok"
	}
	return "degraded"
}

// ComputeNodeHealthScore calculates health score for a node.
func ComputeNodeHealthScore(latency *int, speedMbps float64, failures int, enabled bool) (int, string) {
	if !enabled {
		return 0, "disabled"
	}
	var latencyPoints int
	switch {
	case latency == nil:
		latencyPoints = 42
	case *latency < 0:
		latencyPoints = 5
	case *latency <= 80:
		latencyPoints = 55
	case *latency <= 180:
		latencyPoints = 45
	case *latency <= 350:
		latencyPoints = 32
	default:
		latencyPoints = 15
	}

	var speedPoints int
	switch {
	case speedMbps <= 0:
		speedPoints = 30
	case speedMbps >= 50:
		speedPoints = 45
	case speedMbps >= 20:
		speedPoints = 40
	case speedMbps >= 5:
		speedPoints = 35
	default:
		speedPoints = 25
	}

	penalty := failures * 8
	score := latencyPoints + speedPoints - penalty
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	var status string
	switch {
	case score >= 70:
		status = "healthy"
	case score >= 40:
		status = "degraded"
	default:
		status = "unhealthy"
	}

	return score, status
}

// NodeSortKey returns a sortable tuple for ordering nodes by health.
func NodeSortKey(n state.Node) (int, int, string) {
	score := n.HealthScore
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	latencyVal := 9000
	if n.Latency != nil {
		latencyVal = *n.Latency
		if latencyVal < 0 {
			latencyVal = 10000
		}
	}
	return -score, latencyVal, n.Tag
}

// FormatChecksSummary returns a compact string summary of health check results.
func FormatChecksSummary(checks map[string]CheckResult) string {
	var parts []string
	for name, c := range checks {
		parts = append(parts, fmt.Sprintf("%s=%s", name, c.Status))
	}
	return strings.Join(parts, " ")
}
