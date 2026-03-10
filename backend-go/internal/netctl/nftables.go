package netctl

import (
	"fmt"
	"regexp"
	"strings"
)

// CommonDohIPv4 are well-known DoH/DoT server IPs to block.
var CommonDohIPv4 = []string{
	"1.0.0.1", "1.1.1.1", "1.1.1.2", "1.1.1.3",
	"8.8.4.4", "8.8.8.8",
	"9.9.9.9", "9.9.9.10", "9.9.9.11",
	"149.112.112.112",
	"208.67.220.220", "208.67.222.222",
	"94.140.14.14", "94.140.15.15",
	"185.228.168.168", "185.228.169.169",
}

// CommonDohIPv6 are well-known DoH/DoT server IPv6 addresses.
var CommonDohIPv6 = []string{
	"2606:4700:4700::1111", "2606:4700:4700::1001",
	"2001:4860:4860::8888", "2001:4860:4860::8844",
	"2620:fe::fe", "2620:fe::9",
}

var macRE = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

// NftDevice represents a managed device for nftables rule generation.
type NftDevice struct {
	MAC  string
	Mark int
}

// NftConfig contains all parameters for nftables ruleset generation.
type NftConfig struct {
	Enabled       bool
	Devices       []NftDevice
	DNSPort       int
	DNSServers    []string
	DefaultPolicy string // "whitelist", "blacklist", "block", "allow"
	FailurePolicy string // "fail-close", "fail-open"
	FailCloseActive bool
	LANIface      string
	ListenPort    int
}

// RenderNftRuleset generates a complete nftables script from config.
// Returns the script content to feed to `nft -f -`.
func RenderNftRuleset(cfg NftConfig) string {
	if !cfg.Enabled || len(cfg.Devices) == 0 {
		return "# macflow disabled or no devices\n"
	}

	dnsPort := cfg.DNSPort
	if dnsPort == 0 {
		dnsPort = 6053
	}
	listenPort := cfg.ListenPort
	if listenPort == 0 {
		listenPort = 8080
	}
	lanIface := cfg.LANIface
	if lanIface == "" {
		lanIface = "br-lan"
	}

	// Filter valid MACs
	var validDevices []NftDevice
	for _, d := range cfg.Devices {
		if macRE.MatchString(d.MAC) && d.Mark > 0 {
			validDevices = append(validDevices, d)
		}
	}
	if len(validDevices) == 0 {
		return "# no valid managed devices\n"
	}

	// Build mac_to_mark elements
	var mapElements []string
	var macElements []string
	for _, d := range validDevices {
		mapElements = append(mapElements, fmt.Sprintf("      %s : 0x%x", d.MAC, d.Mark))
		macElements = append(macElements, fmt.Sprintf("      %s", d.MAC))
	}

	// Build DoH IP sets
	dohIPv4 := make([]string, len(CommonDohIPv4))
	copy(dohIPv4, CommonDohIPv4)
	for _, s := range cfg.DNSServers {
		// Add DNS servers to DoH block list
		if strings.Contains(s, ".") { // IPv4
			dohIPv4 = appendUnique(dohIPv4, s)
		}
	}

	var dohV4Elements []string
	for _, ip := range dohIPv4 {
		dohV4Elements = append(dohV4Elements, fmt.Sprintf("      %s", ip))
	}
	var dohV6Elements []string
	for _, ip := range CommonDohIPv6 {
		dohV6Elements = append(dohV6Elements, fmt.Sprintf("      %s", ip))
	}

	// Determine unresolved devices (have mark but no resolved IP)
	// For now, treat all devices as resolved; unresolved detection
	// will be populated by runtime refresh

	var sb strings.Builder

	// Delete existing table then recreate (ignore delete errors in Go code)
	sb.WriteString("table inet macflow {\n\n")

	// mac_to_mark map
	sb.WriteString("  map mac_to_mark {\n")
	sb.WriteString("    type ether_addr : mark\n")
	sb.WriteString("    elements = {\n")
	sb.WriteString(strings.Join(mapElements, ",\n"))
	sb.WriteString("\n    }\n")
	sb.WriteString("  }\n\n")

	// managed_macs set
	sb.WriteString("  set managed_macs {\n")
	sb.WriteString("    type ether_addr\n")
	sb.WriteString("    elements = {\n")
	sb.WriteString(strings.Join(macElements, ",\n"))
	sb.WriteString("\n    }\n")
	sb.WriteString("  }\n\n")

	// DoH IPv4 set
	sb.WriteString("  set doh_ipv4 {\n")
	sb.WriteString("    type ipv4_addr\n")
	sb.WriteString("    elements = {\n")
	sb.WriteString(strings.Join(dohV4Elements, ",\n"))
	sb.WriteString("\n    }\n")
	sb.WriteString("  }\n\n")

	// DoH IPv6 set
	sb.WriteString("  set doh_ipv6 {\n")
	sb.WriteString("    type ipv6_addr\n")
	sb.WriteString("    elements = {\n")
	sb.WriteString(strings.Join(dohV6Elements, ",\n"))
	sb.WriteString("\n    }\n")
	sb.WriteString("  }\n\n")

	// ── Chain: prerouting_mark ──
	sb.WriteString("  chain prerouting_mark {\n")
	sb.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
	sb.WriteString("    ct mark != 0x0 meta mark set ct mark\n")
	sb.WriteString("    ct state new ether saddr @managed_macs meta mark set ether saddr map @mac_to_mark\n")
	sb.WriteString("    ct state new ct mark set meta mark\n")
	sb.WriteString("  }\n\n")

	// ── Chain: dns_guard ──
	sb.WriteString("  chain dns_guard {\n")
	sb.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	sb.WriteString(fmt.Sprintf("    meta mark != 0x0 udp dport 53 counter redirect to :%d\n", dnsPort))
	sb.WriteString(fmt.Sprintf("    meta mark != 0x0 tcp dport 53 counter redirect to :%d\n", dnsPort))
	sb.WriteString("  }\n\n")

	// ── Chain: forward_guard ──
	sb.WriteString("  chain forward_guard {\n")
	sb.WriteString("    type filter hook forward priority filter; policy accept;\n")

	// Block DoH/DoT/DoQ/QUIC
	sb.WriteString("    meta mark != 0x0 ip daddr @doh_ipv4 tcp dport 443 counter drop\n")
	sb.WriteString("    meta mark != 0x0 ip daddr @doh_ipv4 udp dport 443 counter drop\n")
	sb.WriteString("    meta mark != 0x0 ip6 daddr @doh_ipv6 tcp dport 443 counter drop\n")
	sb.WriteString("    meta mark != 0x0 ip6 daddr @doh_ipv6 udp dport 443 counter drop\n")
	sb.WriteString("    meta mark != 0x0 tcp dport 853 counter drop\n")  // DoT
	sb.WriteString("    meta mark != 0x0 udp dport 853 counter drop\n")
	sb.WriteString("    meta mark != 0x0 udp dport 8853 counter drop\n") // DoQ
	sb.WriteString("    meta mark != 0x0 udp dport 784 counter drop\n")  // QUIC
	sb.WriteString("    meta mark != 0x0 udp dport 3478 counter drop\n") // STUN
	sb.WriteString("    meta mark != 0x0 tcp dport 3478 counter drop\n")
	sb.WriteString("    meta mark != 0x0 udp dport 5349 counter drop\n") // TURN

	// Fail-close: block non-tunnel traffic
	if cfg.FailCloseActive || cfg.FailurePolicy == "fail-close" {
		sb.WriteString("    # fail-close: block non-tunnel traffic\n")
		sb.WriteString("    meta mark != 0x0 oifname != \"singtun0\" ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop\n")
	}

	sb.WriteString("  }\n\n")

	// ── Chain: ipv6_guard ──
	sb.WriteString("  chain ipv6_guard {\n")
	sb.WriteString("    type filter hook forward priority filter; policy accept;\n")
	sb.WriteString("    meta mark != 0x0 ip6 daddr != fe80::/10 ip6 daddr != ::1 counter drop\n")
	sb.WriteString("  }\n\n")

	// ── Chain: captive_redirect (whitelist/block mode) ──
	if cfg.DefaultPolicy == "whitelist" || cfg.DefaultPolicy == "block" {
		sb.WriteString("  chain captive_redirect {\n")
		sb.WriteString("    type nat hook prerouting priority dstnat + 10; policy accept;\n")
		sb.WriteString(fmt.Sprintf("    iifname \"%s\" ether saddr @managed_macs accept\n", lanIface))
		sb.WriteString(fmt.Sprintf("    iifname \"%s\" tcp dport 80 counter redirect to :%d\n", lanIface, listenPort))
		sb.WriteString("  }\n\n")
	}

	sb.WriteString("}\n")
	return sb.String()
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
