package netctl

import (
	"strings"
	"testing"
)

func TestRenderNftRuleset_Disabled(t *testing.T) {
	cfg := NftConfig{Enabled: false, Devices: []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100}}}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "disabled") {
		t.Errorf("disabled config should return disabled comment, got: %s", got)
	}
}

func TestRenderNftRuleset_NoDevices(t *testing.T) {
	cfg := NftConfig{Enabled: true, Devices: nil}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "disabled") && !strings.Contains(got, "no") {
		t.Errorf("empty devices should return disabled/no-devices comment, got: %s", got)
	}
}

func TestRenderNftRuleset_InvalidMAC(t *testing.T) {
	cfg := NftConfig{
		Enabled: true,
		Devices: []NftDevice{
			{MAC: "not-a-mac", Mark: 0x100},
			{MAC: "AA:BB:CC:DD:EE", Mark: 0x101}, // too short
		},
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "no valid") {
		t.Errorf("all invalid MACs should return no-valid comment, got: %s", got)
	}
}

func TestRenderNftRuleset_ZeroMark(t *testing.T) {
	cfg := NftConfig{
		Enabled: true,
		Devices: []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0}},
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "no valid") {
		t.Errorf("zero mark should be invalid, got: %s", got)
	}
}

func TestRenderNftRuleset_BasicValid(t *testing.T) {
	cfg := NftConfig{
		Enabled: true,
		Devices: []NftDevice{
			{MAC: "AA:BB:CC:DD:EE:01", Mark: 0x100},
			{MAC: "AA:BB:CC:DD:EE:02", Mark: 0x101},
		},
		DNSPort:       6053,
		LANIface:      "br-lan",
		ListenPort:    8080,
		FailurePolicy: "fail-open",
	}
	got := RenderNftRuleset(cfg)

	checks := []struct {
		name    string
		contain string
	}{
		{"table declaration", "table inet macflow"},
		{"mac_to_mark map", "map mac_to_mark"},
		{"device 1 MAC", "AA:BB:CC:DD:EE:01"},
		{"device 2 MAC", "AA:BB:CC:DD:EE:02"},
		{"device 1 mark", "0x100"},
		{"device 2 mark", "0x101"},
		{"managed_macs set", "set managed_macs"},
		{"doh_ipv4 set", "set doh_ipv4"},
		{"doh_ipv6 set", "set doh_ipv6"},
		{"prerouting_mark chain", "chain prerouting_mark"},
		{"dns_guard chain", "chain dns_guard"},
		{"forward_guard chain", "chain forward_guard"},
		{"ipv6_guard chain", "chain ipv6_guard"},
		{"dns redirect port", "redirect to :6053"},
		{"DoT block", "tcp dport 853"},
		{"DoQ block", "udp dport 8853"},
		{"QUIC block", "udp dport 784"},
		{"1.1.1.1 in doh set", "1.1.1.1"},
		{"8.8.8.8 in doh set", "8.8.8.8"},
	}
	for _, c := range checks {
		if !strings.Contains(got, c.contain) {
			t.Errorf("%s: expected output to contain %q", c.name, c.contain)
		}
	}

	// fail-open should NOT have fail-close block
	if strings.Contains(got, "fail-close") {
		t.Error("fail-open mode should not contain fail-close rules")
	}

	// Should NOT have captive_redirect for non-whitelist policy
	if strings.Contains(got, "captive_redirect") {
		t.Error("default policy (empty) should not produce captive_redirect chain")
	}
}

func TestRenderNftRuleset_FailClose(t *testing.T) {
	cfg := NftConfig{
		Enabled:       true,
		Devices:       []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100}},
		FailurePolicy: "fail-close",
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "fail-close") {
		t.Error("fail-close mode should contain fail-close comment")
	}
	if !strings.Contains(got, "singtun0") {
		t.Error("fail-close should reference singtun0 interface")
	}
}

func TestRenderNftRuleset_FailCloseActive(t *testing.T) {
	cfg := NftConfig{
		Enabled:         true,
		Devices:         []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100}},
		FailCloseActive: true,
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "fail-close") {
		t.Error("FailCloseActive should trigger fail-close rules")
	}
}

func TestRenderNftRuleset_CaptiveRedirect_Whitelist(t *testing.T) {
	cfg := NftConfig{
		Enabled:       true,
		Devices:       []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100}},
		DefaultPolicy: "whitelist",
		LANIface:      "eth0",
		ListenPort:    9090,
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "captive_redirect") {
		t.Error("whitelist policy should produce captive_redirect chain")
	}
	if !strings.Contains(got, "eth0") {
		t.Error("captive_redirect should use configured LAN interface")
	}
	if !strings.Contains(got, "redirect to :9090") {
		t.Error("captive_redirect should use configured listen port")
	}
}

func TestRenderNftRuleset_CaptiveRedirect_Block(t *testing.T) {
	cfg := NftConfig{
		Enabled:       true,
		Devices:       []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100}},
		DefaultPolicy: "block",
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "captive_redirect") {
		t.Error("block policy should produce captive_redirect chain")
	}
}

func TestRenderNftRuleset_NoCaptive_Blacklist(t *testing.T) {
	cfg := NftConfig{
		Enabled:       true,
		Devices:       []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100}},
		DefaultPolicy: "blacklist",
	}
	got := RenderNftRuleset(cfg)
	if strings.Contains(got, "captive_redirect") {
		t.Error("blacklist policy should NOT produce captive_redirect chain")
	}
}

func TestRenderNftRuleset_Defaults(t *testing.T) {
	cfg := NftConfig{
		Enabled: true,
		Devices: []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100}},
		// All zero/empty → should use defaults
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "redirect to :6053") {
		t.Error("default DNS port should be 6053")
	}
	// No captive_redirect with empty policy
	if strings.Contains(got, "captive_redirect") {
		t.Error("empty policy should not produce captive_redirect")
	}
}

func TestRenderNftRuleset_CustomDNSServers(t *testing.T) {
	cfg := NftConfig{
		Enabled:    true,
		Devices:    []NftDevice{{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100}},
		DNSServers: []string{"192.168.1.1"},
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "192.168.1.1") {
		t.Error("custom DNS server should appear in doh_ipv4 set")
	}
}

func TestRenderNftRuleset_LowercaseMAC(t *testing.T) {
	cfg := NftConfig{
		Enabled: true,
		Devices: []NftDevice{{MAC: "aa:bb:cc:dd:ee:ff", Mark: 0x100}},
	}
	got := RenderNftRuleset(cfg)
	if !strings.Contains(got, "aa:bb:cc:dd:ee:ff") {
		t.Error("lowercase MAC should be accepted")
	}
	if strings.Contains(got, "no valid") {
		t.Error("lowercase MAC should be valid")
	}
}

func TestRenderNftRuleset_MixedValidAndInvalid(t *testing.T) {
	cfg := NftConfig{
		Enabled: true,
		Devices: []NftDevice{
			{MAC: "not-valid", Mark: 0x100},
			{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x101},
			{MAC: "11:22:33:44:55:66", Mark: 0},  // zero mark
		},
	}
	got := RenderNftRuleset(cfg)
	// Should have only the one valid device
	if !strings.Contains(got, "AA:BB:CC:DD:EE:FF") {
		t.Error("valid device should appear")
	}
	if strings.Contains(got, "not-valid") {
		t.Error("invalid MAC should be filtered out")
	}
	if !strings.Contains(got, "0x101") {
		t.Error("valid device mark should appear")
	}
}

func TestAppendUnique(t *testing.T) {
	s1 := []string{"a", "b", "c"}
	s2 := appendUnique(s1, "b")
	if len(s2) != 3 {
		t.Errorf("appendUnique should not duplicate, got len=%d", len(s2))
	}
	s3 := appendUnique(s1, "d")
	if len(s3) != 4 {
		t.Errorf("appendUnique should append new, got len=%d", len(s3))
	}
}
