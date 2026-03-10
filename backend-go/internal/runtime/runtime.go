// Package runtime manages the sing-box + nftables + ip-rules lifecycle.
// It orchestrates the full apply pipeline: render config → apply nft → write
// sing-box config → reload → apply ip rules.
package runtime

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"macflow/internal/netctl"
	"macflow/internal/singbox"
	"macflow/internal/state"
)

// Manager handles runtime network operations.
type Manager struct {
	store  *state.Store
	mu     sync.Mutex // apply lock — only one apply at a time

	// Fail-close guard state
	FailCloseActive bool
	FailCloseSince  int64
	FailCloseReason string
}

// NewManager creates a new runtime manager.
func NewManager(store *state.Store) *Manager {
	return &Manager{store: store}
}

// HotApplyResult contains the result of a hot-apply operation.
type HotApplyResult struct {
	Singbox  string `json:"singbox"`
	Nftables string `json:"nftables"`
	IPRules  string `json:"ip_rules"`
}

// HotApply regenerates sing-box config + nftables rules + ip rules
// and applies them atomically.
func (m *Manager) HotApply(allowRestart bool) HotApplyResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := m.store.Read()

	if !st.Enabled {
		log.Printf("[runtime] service disabled, skipping hot_apply")
		return HotApplyResult{
			Singbox:  "skipped (disabled)",
			Nftables: "skipped (disabled)",
			IPRules:  "skipped (disabled)",
		}
	}

	result := HotApplyResult{}

	// 1. Build and write sing-box config
	configJSON, err := singbox.ConfigJSON(st)
	if err != nil {
		result.Singbox = fmt.Sprintf("error: %v", err)
	} else {
		if err := singbox.WriteConfig(configJSON); err != nil {
			result.Singbox = fmt.Sprintf("write error: %v", err)
		} else {
			result.Singbox = singbox.Reload()
		}
	}

	// 2. Render and apply nftables
	nftCfg := m.buildNftConfig(st)
	nftScript := netctl.RenderNftRuleset(nftCfg)
	if err := m.applyNftScript(nftScript); err != nil {
		result.Nftables = fmt.Sprintf("error: %v", err)
	} else {
		result.Nftables = "applied"
	}

	// 3. Apply IP rules
	marks := m.collectMarks(st)
	mode := st.DefaultPolicy
	ipResult, err := netctl.ApplyIPRules(marks, mode)
	if err != nil {
		result.IPRules = fmt.Sprintf("error: %v", err)
	} else {
		result.IPRules = ipResult
	}

	log.Printf("[runtime] hot_apply complete: singbox=%s nft=%s iprules=%s",
		result.Singbox, result.Nftables, result.IPRules)

	return result
}

// StopAll flushes nftables, clears ip rules, stops sing-box.
func (m *Manager) StopAll() HotApplyResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := HotApplyResult{}

	// Flush nftables – delete table directly (shell redirects are invalid in nft scripts)
	if err := m.applyNftScript("delete table inet macflow\n"); err != nil {
		result.Nftables = fmt.Sprintf("flush error: %v", err)
	} else {
		result.Nftables = "flushed"
	}

	// Flush IP rules
	if err := netctl.FlushIPRules(); err != nil {
		result.IPRules = fmt.Sprintf("flush error: %v", err)
	} else {
		result.IPRules = "flushed"
	}

	// Stop sing-box
	result.Singbox = singbox.Stop()

	// Clear fail-close guard
	m.FailCloseActive = false
	m.FailCloseSince = 0
	m.FailCloseReason = ""

	log.Printf("[runtime] stop_all complete")
	return result
}

// buildNftConfig constructs NftConfig from state.
func (m *Manager) buildNftConfig(st state.State) netctl.NftConfig {
	var devices []netctl.NftDevice
	for _, d := range st.Devices {
		if d.Managed && d.Mark > 0 {
			devices = append(devices, netctl.NftDevice{
				MAC:  d.MAC,
				Mark: d.Mark,
			})
		}
	}

	lanIface := netctl.DetectLANIface()

	return netctl.NftConfig{
		Enabled:         st.Enabled,
		Devices:         devices,
		DNSPort:         st.DNS.EnforceRedirectPort,
		DNSServers:      st.DNS.Servers,
		DefaultPolicy:   st.DefaultPolicy,
		FailurePolicy:   st.FailurePolicy,
		FailCloseActive: m.FailCloseActive,
		LANIface:        lanIface,
		ListenPort:      8080,
	}
}

// collectMarks returns all active marks from managed devices.
func (m *Manager) collectMarks(st state.State) []int {
	var marks []int
	for _, d := range st.Devices {
		if d.Managed && d.Mark > 0 {
			marks = append(marks, d.Mark)
		}
	}
	return marks
}

// applyNftScript feeds an nft script to `nft -f -`.
func (m *Manager) applyNftScript(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f -: %s: %w", string(out), err)
	}
	return nil
}

// ── RuntimeApplier interface methods (used by health.Monitor probe loop) ──

// SetFailClose activates or deactivates the fail-close guard.
func (m *Manager) SetFailClose(active bool, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FailCloseActive = active
	if active {
		m.FailCloseSince = time.Now().Unix()
		m.FailCloseReason = reason
	} else {
		m.FailCloseSince = 0
		m.FailCloseReason = ""
	}
}

// IsFailCloseActive returns whether fail-close guard is currently active.
func (m *Manager) IsFailCloseActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.FailCloseActive
}

// TriggerApply is a convenience method implementing health.RuntimeApplier.
// It calls HotApply(false) and discards the result.
func (m *Manager) TriggerApply() {
	m.HotApply(false)
}

// GetFailCloseActive returns the current fail-close active state.
func (m *Manager) GetFailCloseActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.FailCloseActive
}

// GetFailCloseSince returns the timestamp when fail-close was activated.
func (m *Manager) GetFailCloseSince() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.FailCloseSince
}

// GetFailCloseReason returns the reason for fail-close activation.
func (m *Manager) GetFailCloseReason() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.FailCloseReason
}

