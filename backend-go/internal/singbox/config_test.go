package singbox

import (
	"encoding/json"
	"strings"
	"testing"

	"macflow/internal/state"
)

func newTestState() state.State {
	return state.State{
		DNS: state.DNSConfig{
			Servers:             []string{"8.8.8.8"},
			EnforceRedirectPort: 6053,
		},
		Nodes: []state.Node{
			{
				Type:       "shadowsocks",
				Tag:        "ss-node",
				Server:     "1.2.3.4",
				ServerPort: 8388,
				Method:     "aes-256-gcm",
				Password:   "pass123",
				Enabled:    true,
			},
			{
				Type:       "vmess",
				Tag:        "vmess-node",
				Server:     "5.6.7.8",
				ServerPort: 443,
				UUID:       "uuid-1234",
				Enabled:    true,
			},
		},
		Devices: []state.Device{
			{
				MAC:     "AA:BB:CC:DD:EE:01",
				IP:      "192.168.1.100",
				NodeTag: "ss-node",
				Managed: true,
			},
		},
	}
}

func TestBuildConfig_Structure(t *testing.T) {
	st := newTestState()
	cfg, err := BuildConfig(st)
	if err != nil {
		t.Fatalf("BuildConfig failed: %v", err)
	}

	requiredKeys := []string{"log", "dns", "inbounds", "outbounds", "route", "experimental"}
	for _, k := range requiredKeys {
		if _, ok := cfg[k]; !ok {
			t.Errorf("config missing key: %s", k)
		}
	}
}

func TestBuildConfig_DNS(t *testing.T) {
	st := newTestState()
	cfg, _ := BuildConfig(st)

	dnsRaw := cfg["dns"].(map[string]interface{})
	servers := dnsRaw["servers"].([]map[string]interface{})

	// Should have per-server entries + local-dns
	if len(servers) < 2 {
		t.Errorf("expected at least 2 dns servers, got %d", len(servers))
	}

	// Last server should be local-dns
	last := servers[len(servers)-1]
	if last["tag"] != "local-dns" {
		t.Errorf("last DNS server should be local-dns, got %v", last["tag"])
	}
}

func TestBuildConfig_Inbounds(t *testing.T) {
	st := newTestState()
	cfg, _ := BuildConfig(st)

	inbounds := cfg["inbounds"].([]map[string]interface{})
	if len(inbounds) != 3 {
		t.Fatalf("expected 3 inbounds (tun, dns, mixed), got %d", len(inbounds))
	}

	types := map[string]bool{}
	for _, ib := range inbounds {
		types[ib["type"].(string)] = true
	}
	for _, exp := range []string{"tun", "direct", "mixed"} {
		if !types[exp] {
			t.Errorf("missing inbound type: %s", exp)
		}
	}
}

func TestBuildConfig_Outbounds(t *testing.T) {
	st := newTestState()
	cfg, _ := BuildConfig(st)

	outbounds := cfg["outbounds"].([]map[string]interface{})
	// selector + 2 nodes + direct-out = 4
	if len(outbounds) < 4 {
		t.Errorf("expected at least 4 outbounds, got %d", len(outbounds))
	}

	// First should be selector
	if outbounds[0]["type"] != "selector" {
		t.Errorf("first outbound should be selector, got %v", outbounds[0]["type"])
	}
	if outbounds[0]["tag"] != "proxy-select" {
		t.Errorf("selector tag should be proxy-select, got %v", outbounds[0]["tag"])
	}
}

func TestBuildConfig_SelectorDefault(t *testing.T) {
	st := newTestState()
	cfg, _ := BuildConfig(st)

	outbounds := cfg["outbounds"].([]map[string]interface{})
	selector := outbounds[0]

	// Default should be the first enabled node (sorted by health)
	def := selector["default"].(string)
	if def == "direct-out" {
		t.Error("default should be a node tag, not direct-out when nodes exist")
	}
}

func TestBuildConfig_DisabledNodesExcluded(t *testing.T) {
	st := newTestState()
	st.Nodes[1].Enabled = false // disable vmess-node

	cfg, _ := BuildConfig(st)
	outbounds := cfg["outbounds"].([]map[string]interface{})

	for _, ob := range outbounds {
		if ob["tag"] == "vmess-node" {
			t.Error("disabled node should not appear in outbounds")
		}
	}
}

func TestBuildConfig_NoNodes(t *testing.T) {
	st := newTestState()
	st.Nodes = nil

	cfg, _ := BuildConfig(st)
	outbounds := cfg["outbounds"].([]map[string]interface{})

	// Should still have selector + direct-out
	if len(outbounds) < 2 {
		t.Errorf("even with no nodes, should have selector + direct-out, got %d", len(outbounds))
	}
	selector := outbounds[0]
	if selector["default"] != "direct-out" {
		t.Errorf("with no nodes, default should be direct-out, got %v", selector["default"])
	}
}

func TestBuildConfig_DeviceRouting(t *testing.T) {
	st := newTestState()
	cfg, _ := BuildConfig(st)

	route := cfg["route"].(map[string]interface{})
	rules := route["rules"].([]map[string]interface{})

	// Should have a rule with source_ip_cidr for the device
	found := false
	for _, r := range rules {
		if cidrs, ok := r["source_ip_cidr"]; ok {
			cidrList := cidrs.([]string)
			for _, c := range cidrList {
				if strings.Contains(c, "192.168.1.100") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("device with IP 192.168.1.100 should have a routing rule")
	}
}

func TestBuildConfig_DirectDeviceSkipped(t *testing.T) {
	st := newTestState()
	st.Devices[0].NodeTag = "direct"

	cfg, _ := BuildConfig(st)
	route := cfg["route"].(map[string]interface{})
	rules := route["rules"].([]map[string]interface{})

	for _, r := range rules {
		if cidrs, ok := r["source_ip_cidr"]; ok {
			cidrList := cidrs.([]string)
			for _, c := range cidrList {
				if strings.Contains(c, "192.168.1.100") {
					t.Error("device with nodeTag=direct should not have routing rule")
				}
			}
		}
	}
}

func TestBuildConfig_UnmanagedDeviceSkipped(t *testing.T) {
	st := newTestState()
	st.Devices[0].Managed = false

	cfg, _ := BuildConfig(st)
	route := cfg["route"].(map[string]interface{})
	rules := route["rules"].([]map[string]interface{})

	for _, r := range rules {
		if cidrs, ok := r["source_ip_cidr"]; ok {
			cidrList := cidrs.([]string)
			for _, c := range cidrList {
				if strings.Contains(c, "192.168.1.100") {
					t.Error("unmanaged device should not have routing rule")
				}
			}
		}
	}
}

func TestBuildConfig_DefaultDNS(t *testing.T) {
	st := newTestState()
	st.DNS.Servers = nil // empty

	cfg, _ := BuildConfig(st)
	dnsRaw := cfg["dns"].(map[string]interface{})
	finalDNS := dnsRaw["final"].(string)

	// Should fall back to 8.8.8.8
	if !strings.Contains(finalDNS, "8.8.8.8") {
		t.Errorf("default DNS final should reference 8.8.8.8, got %s", finalDNS)
	}
}

func TestConfigJSON_ValidJSON(t *testing.T) {
	st := newTestState()
	data, err := ConfigJSON(st)
	if err != nil {
		t.Fatalf("ConfigJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("ConfigJSON output is not valid JSON: %v", err)
	}

	if _, ok := parsed["outbounds"]; !ok {
		t.Error("JSON output missing outbounds key")
	}
}

func TestNodeToOutbound_Shadowsocks(t *testing.T) {
	n := state.Node{
		Type:       "shadowsocks",
		Tag:        "ss-1",
		Server:     "1.2.3.4",
		ServerPort: 8388,
		Method:     "aes-256-gcm",
		Password:   "pass",
	}
	ob := nodeToOutbound(n)
	if ob["type"] != "shadowsocks" {
		t.Errorf("type = %v, want shadowsocks", ob["type"])
	}
	if ob["method"] != "aes-256-gcm" {
		t.Errorf("method = %v, want aes-256-gcm", ob["method"])
	}
	if ob["password"] != "pass" {
		t.Errorf("password = %v, want pass", ob["password"])
	}
}

func TestNodeToOutbound_Vmess(t *testing.T) {
	n := state.Node{
		Type:       "vmess",
		Tag:        "vm-1",
		Server:     "1.2.3.4",
		ServerPort: 443,
		UUID:       "uid-123",
		Security:   "auto",
	}
	ob := nodeToOutbound(n)
	if ob["uuid"] != "uid-123" {
		t.Errorf("uuid = %v", ob["uuid"])
	}
	if ob["security"] != "auto" {
		t.Errorf("security = %v, want auto", ob["security"])
	}
}

func TestNodeToOutbound_VmessDefaultSecurity(t *testing.T) {
	n := state.Node{
		Type:       "vmess",
		Tag:        "vm-2",
		Server:     "x.y.z",
		ServerPort: 443,
		UUID:       "uid",
	}
	ob := nodeToOutbound(n)
	if ob["security"] != "auto" {
		t.Errorf("vmess default security should be auto, got %v", ob["security"])
	}
}

func TestNodeToOutbound_Vless(t *testing.T) {
	n := state.Node{
		Type:       "vless",
		Tag:        "vl-1",
		Server:     "1.2.3.4",
		ServerPort: 443,
		UUID:       "uid-456",
		Flow:       "xtls-rprx-vision",
	}
	ob := nodeToOutbound(n)
	if ob["uuid"] != "uid-456" {
		t.Errorf("uuid = %v", ob["uuid"])
	}
	if ob["flow"] != "xtls-rprx-vision" {
		t.Errorf("flow = %v", ob["flow"])
	}
}

func TestNodeToOutbound_VlessNoFlow(t *testing.T) {
	n := state.Node{
		Type:       "vless",
		Tag:        "vl-2",
		Server:     "x",
		ServerPort: 443,
		UUID:       "uid",
	}
	ob := nodeToOutbound(n)
	if _, ok := ob["flow"]; ok {
		t.Error("vless without flow should not have flow key")
	}
}

func TestNodeToOutbound_Trojan(t *testing.T) {
	n := state.Node{
		Type:       "trojan",
		Tag:        "tr-1",
		Server:     "1.2.3.4",
		ServerPort: 443,
		Password:   "trojanpass",
	}
	ob := nodeToOutbound(n)
	if ob["password"] != "trojanpass" {
		t.Errorf("password = %v", ob["password"])
	}
}

func TestNodeToOutbound_Hysteria2(t *testing.T) {
	n := state.Node{
		Type:       "hysteria2",
		Tag:        "hy2-1",
		Server:     "1.2.3.4",
		ServerPort: 443,
		Password:   "hy2pass",
		Transport: map[string]interface{}{
			"type":     "salamander",
			"password": "obfspass",
		},
	}
	ob := nodeToOutbound(n)
	if ob["password"] != "hy2pass" {
		t.Errorf("password = %v", ob["password"])
	}
	obfs, ok := ob["obfs"].(map[string]interface{})
	if !ok {
		t.Fatal("hysteria2 with obfs should have obfs field")
	}
	if obfs["type"] != "salamander" {
		t.Errorf("obfs type = %v", obfs["type"])
	}
	// Transport should NOT be included for hysteria2
	if _, ok := ob["transport"]; ok {
		t.Error("hysteria2 should not have transport key (uses obfs instead)")
	}
}

func TestNodeToOutbound_Tuic(t *testing.T) {
	n := state.Node{
		Type:       "tuic",
		Tag:        "tuic-1",
		Server:     "1.2.3.4",
		ServerPort: 443,
		UUID:       "uid-tuic",
		Password:   "tuicpass",
	}
	ob := nodeToOutbound(n)
	if ob["uuid"] != "uid-tuic" {
		t.Errorf("uuid = %v", ob["uuid"])
	}
	if ob["password"] != "tuicpass" {
		t.Errorf("password = %v", ob["password"])
	}
}

func TestNodeToOutbound_Socks(t *testing.T) {
	n := state.Node{
		Type:       "socks",
		Tag:        "socks-1",
		Server:     "1.2.3.4",
		ServerPort: 1080,
		Username:   "user",
		Password:   "pass",
	}
	ob := nodeToOutbound(n)
	if ob["username"] != "user" {
		t.Errorf("username = %v", ob["username"])
	}
	if ob["password"] != "pass" {
		t.Errorf("password = %v", ob["password"])
	}
}

func TestNodeToOutbound_SocksNoAuth(t *testing.T) {
	n := state.Node{
		Type:       "socks",
		Tag:        "socks-2",
		Server:     "1.2.3.4",
		ServerPort: 1080,
	}
	ob := nodeToOutbound(n)
	if _, ok := ob["username"]; ok {
		t.Error("socks without username should not have username key")
	}
	if _, ok := ob["password"]; ok {
		t.Error("socks without password should not have password key")
	}
}

func TestNodeToOutbound_WithTLS(t *testing.T) {
	n := state.Node{
		Type:       "trojan",
		Tag:        "tls-test",
		Server:     "x.y.z",
		ServerPort: 443,
		Password:   "p",
		TLS: map[string]interface{}{
			"enabled":     true,
			"server_name": "example.com",
		},
	}
	ob := nodeToOutbound(n)
	tls, ok := ob["tls"].(map[string]interface{})
	if !ok {
		t.Fatal("should have tls field")
	}
	if tls["server_name"] != "example.com" {
		t.Errorf("server_name = %v", tls["server_name"])
	}
}

func TestNodeToOutbound_WithTransport(t *testing.T) {
	n := state.Node{
		Type:       "vmess",
		Tag:        "ws-test",
		Server:     "x.y.z",
		ServerPort: 443,
		UUID:       "uid",
		Transport: map[string]interface{}{
			"type": "ws",
			"path": "/ws",
		},
	}
	ob := nodeToOutbound(n)
	tr, ok := ob["transport"].(map[string]interface{})
	if !ok {
		t.Fatal("should have transport field")
	}
	if tr["type"] != "ws" {
		t.Errorf("transport type = %v", tr["type"])
	}
}

func TestOrDefault(t *testing.T) {
	if got := orDefault("hello", "world"); got != "hello" {
		t.Errorf("orDefault(non-empty, def) = %v, want hello", got)
	}
	if got := orDefault("", "world"); got != "world" {
		t.Errorf("orDefault(empty, def) = %v, want world", got)
	}
}
