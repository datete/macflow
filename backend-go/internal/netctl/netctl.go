// Package netctl provides low-level network control functions:
// nftables rule generation/application, ip rule/route management,
// sing-box lifecycle, and ARP/DHCP discovery.
//
// This replaces the subprocess-heavy Python implementation with
// a mix of direct netlink access and optimized command execution.
package netctl

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"macflow/internal/state"
)

// LAN interface detection with caching
var (
	cachedLANIface string
	lanIfaceExpiry time.Time
)

// DetectLANIface auto-detects the LAN bridge interface (br-lan, br0, etc.).
func DetectLANIface() string {
	if cachedLANIface != "" && time.Now().Before(lanIfaceExpiry) {
		return cachedLANIface
	}
	candidates := []string{"br-lan", "br0", "eth0", "lan0"}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, candidate := range candidates {
			for _, iface := range ifaces {
				if iface.Name == candidate {
					cachedLANIface = candidate
					lanIfaceExpiry = time.Now().Add(5 * time.Minute)
					return candidate
				}
			}
		}
	}
	cachedLANIface = "br-lan"
	lanIfaceExpiry = time.Now().Add(5 * time.Minute)
	return "br-lan"
}

// ResolveMACToIP reads ARP table and DHCP leases to build MAC->IP mapping.
// Uses /proc/net/arp directly instead of subprocess for better performance.
func ResolveMACToIP() map[string]string {
	result := make(map[string]string)

	// Read /proc/net/arp (no subprocess needed!)
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] { // skip header
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				ip := fields[0]
				mac := strings.ToUpper(fields[3])
				if mac != "00:00:00:00:00:00" {
					result[mac] = ip
				}
			}
		}
	}

	// Read DHCP leases
	for _, leaseFile := range []string{"/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases"} {
		if data, err := os.ReadFile(leaseFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					result[strings.ToUpper(fields[1])] = fields[2]
				}
			}
		}
	}

	return result
}

// GenerateNftRuleset generates the complete nftables ruleset for macflow.
// This is the Go equivalent of Python's _apply_nftables().
func GenerateNftRuleset(st state.State, macToIP map[string]string, lanIface string) string {
	var b strings.Builder
	b.WriteString("table inet macflow {\n")

	// MAC-to-mark chain
	b.WriteString("  chain mac_to_mark {\n")
	for _, dev := range st.Devices {
		if !dev.Managed || dev.Mark == 0 {
			continue
		}
		mac := strings.ToLower(dev.MAC)
		b.WriteString(fmt.Sprintf("    ether saddr %s meta mark set 0x%x\n", mac, dev.Mark))
	}
	b.WriteString("  }\n\n")

	// DNS guard chain
	if st.DNS.ForceRedirect && st.DNS.EnforceRedirectPort > 0 {
		port := st.DNS.EnforceRedirectPort
		b.WriteString("  chain dns_guard {\n")
		b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
		b.WriteString(fmt.Sprintf("    iifname \"%s\" udp dport 53 counter redirect to :%d\n", lanIface, port))
		b.WriteString(fmt.Sprintf("    iifname \"%s\" tcp dport 53 counter redirect to :%d\n", lanIface, port))
		b.WriteString("  }\n\n")
	}

	// Forward guard (DoH/DoQ/STUN blocking)
	if st.DNS.BlockDOHDOQ {
		b.WriteString("  chain forward_guard {\n")
		b.WriteString("    type filter hook forward priority filter; policy accept;\n")
		// Common DoH IPv4
		b.WriteString("    ip daddr @doh_ipv4 tcp dport 443 counter drop\n")
		b.WriteString("    ip6 daddr @doh_ipv6 tcp dport 443 counter drop\n")
		b.WriteString("    tcp dport 853 counter drop\n")
		b.WriteString("    udp dport 8853 counter drop\n")
		b.WriteString("    udp dport 784 counter drop\n")
		b.WriteString("    udp dport 3478 counter drop\n")
		b.WriteString("    udp dport 5349 counter drop\n")
		b.WriteString("  }\n\n")
	}

	// IPv6 guard
	b.WriteString("  chain ipv6_guard {\n")
	b.WriteString("    type filter hook forward priority filter; policy accept;\n")
	b.WriteString("    ip6 daddr != ::1/128 counter drop\n")
	b.WriteString("  }\n\n")

	// Prerouting (mark setting)
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
	b.WriteString(fmt.Sprintf("    iifname \"%s\" jump mac_to_mark\n", lanIface))
	b.WriteString("  }\n")

	b.WriteString("}\n")
	return b.String()
}

// ApplyNftRuleset loads an nftables ruleset atomically via `nft -f -`.
func ApplyNftRuleset(ruleset string) error {
	// First flush existing table (ignore error if it doesn't exist)
	flushCmd := exec.Command("nft", "delete", "table", "inet", "macflow")
	flushCmd.Run()

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %s: %w", string(out), err)
	}
	return nil
}

// FlushNftables removes the macflow nftables table.
func FlushNftables() error {
	cmd := exec.Command("nft", "flush", "table", "inet", "macflow")
	cmd.Run() // ignore error (table may not exist)
	cmd2 := exec.Command("nft", "delete", "table", "inet", "macflow")
	cmd2.Run() // ignore error
	return nil
}

// IsSingboxRunning checks if sing-box process is active.
// Uses /proc directly for better performance.
func IsSingboxRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// Fallback to pidof
		cmd := exec.Command("pidof", "sing-box")
		return cmd.Run() == nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name[0] < '0' || name[0] > '9' {
			continue
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", name))
		if err == nil && strings.TrimSpace(string(comm)) == "sing-box" {
			return true
		}
	}
	return false
}
