package parsers

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// ── ParseSS ──

func TestParseSS_Valid(t *testing.T) {
	// ss://base64(method:password)@host:port#tag
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:mypassword"))
	link := "ss://" + userinfo + "@1.2.3.4:8388#MyServer"
	node := ParseSS(link)
	if node == nil {
		t.Fatal("ParseSS returned nil for valid link")
	}
	if node.Type != "shadowsocks" {
		t.Errorf("type = %s, want shadowsocks", node.Type)
	}
	if node.Server != "1.2.3.4" {
		t.Errorf("server = %s", node.Server)
	}
	if node.ServerPort != 8388 {
		t.Errorf("port = %d", node.ServerPort)
	}
	if node.Method != "aes-256-gcm" {
		t.Errorf("method = %s", node.Method)
	}
	if node.Password != "mypassword" {
		t.Errorf("password = %s", node.Password)
	}
	if node.Tag != "MyServer" {
		t.Errorf("tag = %s, want MyServer", node.Tag)
	}
	if !node.Enabled {
		t.Error("node should be enabled")
	}
}

func TestParseSS_NoTag(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pass"))
	link := "ss://" + userinfo + "@example.com:1234"
	node := ParseSS(link)
	if node == nil {
		t.Fatal("ParseSS returned nil")
	}
	if node.Tag != "example.com:1234" {
		t.Errorf("tag should default to host:port, got %s", node.Tag)
	}
}

func TestParseSS_Invalid(t *testing.T) {
	cases := []string{
		"ss://",
		"ss://invalid",
		"ss://dGVzdA@:0",     // port 0
		"ss://dGVzdA",        // no @
	}
	for _, c := range cases {
		if node := ParseSS(c); node != nil {
			t.Errorf("ParseSS(%q) should return nil, got %+v", c, node)
		}
	}
}

// ── ParseVmess ──

func TestParseVmess_Valid(t *testing.T) {
	v := map[string]interface{}{
		"add":  "vmess.example.com",
		"port": float64(443),
		"id":   "uuid-1234-5678",
		"ps":   "VMess Node",
		"tls":  "tls",
		"sni":  "vmess.example.com",
		"net":  "ws",
		"path": "/ws",
		"host": "vmess.example.com",
	}
	data, _ := json.Marshal(v)
	link := "vmess://" + base64.StdEncoding.EncodeToString(data)

	node := ParseVmess(link)
	if node == nil {
		t.Fatal("ParseVmess returned nil")
	}
	if node.Type != "vmess" {
		t.Errorf("type = %s", node.Type)
	}
	if node.Server != "vmess.example.com" {
		t.Errorf("server = %s", node.Server)
	}
	if node.ServerPort != 443 {
		t.Errorf("port = %d", node.ServerPort)
	}
	if node.UUID != "uuid-1234-5678" {
		t.Errorf("uuid = %s", node.UUID)
	}
	if node.Tag != "VMess Node" {
		t.Errorf("tag = %s", node.Tag)
	}
	if node.TLS == nil {
		t.Fatal("TLS should be set")
	}
	if node.Transport == nil {
		t.Fatal("Transport should be set for ws")
	}
	if node.Transport["type"] != "ws" {
		t.Errorf("transport type = %v", node.Transport["type"])
	}
}

func TestParseVmess_GrpcTransport(t *testing.T) {
	v := map[string]interface{}{
		"add":  "grpc.example.com",
		"port": float64(443),
		"id":   "uuid-grpc",
		"ps":   "gRPC",
		"net":  "grpc",
		"path": "myservice",
	}
	data, _ := json.Marshal(v)
	link := "vmess://" + base64.StdEncoding.EncodeToString(data)
	node := ParseVmess(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.Transport["type"] != "grpc" {
		t.Errorf("transport type = %v", node.Transport["type"])
	}
	if node.Transport["service_name"] != "myservice" {
		t.Errorf("service_name = %v", node.Transport["service_name"])
	}
}

func TestParseVmess_Invalid(t *testing.T) {
	cases := []string{
		"vmess://",
		"vmess://not-base64!",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"","port":0,"id":""}`)),
	}
	for _, c := range cases {
		if node := ParseVmess(c); node != nil {
			t.Errorf("ParseVmess(%q) should return nil", c)
		}
	}
}

// ── ParseVless ──

func TestParseVless_Valid(t *testing.T) {
	link := "vless://uuid-vless@vless.example.com:443?security=tls&sni=vless.example.com&type=ws&path=/vless&flow=#VLESS%20Node"
	node := ParseVless(link)
	if node == nil {
		t.Fatal("ParseVless returned nil")
	}
	if node.Type != "vless" {
		t.Errorf("type = %s", node.Type)
	}
	if node.UUID != "uuid-vless" {
		t.Errorf("uuid = %s", node.UUID)
	}
	if node.Server != "vless.example.com" {
		t.Errorf("server = %s", node.Server)
	}
	if node.ServerPort != 443 {
		t.Errorf("port = %d", node.ServerPort)
	}
	if node.Tag != "VLESS Node" {
		t.Errorf("tag = %s", node.Tag)
	}
	if node.TLS == nil {
		t.Fatal("TLS should be set")
	}
	if node.Transport == nil {
		t.Fatal("Transport should be set")
	}
}

func TestParseVless_Reality(t *testing.T) {
	link := "vless://uuid-r@reality.com:443?security=reality&sni=www.microsoft.com&pbk=publickey123&sid=shortid456#Reality"
	node := ParseVless(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.TLS == nil {
		t.Fatal("TLS nil")
	}
	reality, ok := node.TLS["reality"].(map[string]interface{})
	if !ok {
		t.Fatal("reality field missing")
	}
	if reality["public_key"] != "publickey123" {
		t.Errorf("public_key = %v", reality["public_key"])
	}
	if reality["short_id"] != "shortid456" {
		t.Errorf("short_id = %v", reality["short_id"])
	}
}

func TestParseVless_WithFlow(t *testing.T) {
	link := "vless://uuid-f@flow.com:443?flow=xtls-rprx-vision#FlowNode"
	node := ParseVless(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.Flow != "xtls-rprx-vision" {
		t.Errorf("flow = %s", node.Flow)
	}
}

func TestParseVless_Invalid(t *testing.T) {
	if node := ParseVless("vless://"); node != nil {
		t.Error("empty vless should return nil")
	}
}

// ── ParseTrojan ──

func TestParseTrojan_Valid(t *testing.T) {
	link := "trojan://mypassword@trojan.example.com:443?sni=trojan.example.com#Trojan%20Node"
	node := ParseTrojan(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.Type != "trojan" {
		t.Errorf("type = %s", node.Type)
	}
	if node.Password != "mypassword" {
		t.Errorf("password = %s", node.Password)
	}
	if node.Server != "trojan.example.com" {
		t.Errorf("server = %s", node.Server)
	}
	if node.ServerPort != 443 {
		t.Errorf("port = %d", node.ServerPort)
	}
	if node.Tag != "Trojan Node" {
		t.Errorf("tag = %s", node.Tag)
	}
	if node.TLS == nil {
		t.Fatal("TLS should be set")
	}
}

func TestParseTrojan_DefaultPort(t *testing.T) {
	link := "trojan://pass@host.com#NoPort"
	node := ParseTrojan(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.ServerPort != 443 {
		t.Errorf("default port should be 443, got %d", node.ServerPort)
	}
}

func TestParseTrojan_WsTransport(t *testing.T) {
	link := "trojan://pass@host.com:443?type=ws&path=/trojan&host=ws.host.com#WS"
	node := ParseTrojan(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.Transport == nil {
		t.Fatal("transport should be set for ws")
	}
	if node.Transport["type"] != "ws" {
		t.Errorf("transport type = %v", node.Transport["type"])
	}
}

// ── ParseHy2 ──

func TestParseHy2_Valid(t *testing.T) {
	link := "hy2://mypassword@hy2.example.com:443?sni=hy2.example.com#HY2%20Node"
	node := ParseHy2(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.Type != "hysteria2" {
		t.Errorf("type = %s", node.Type)
	}
	if node.Password != "mypassword" {
		t.Errorf("password = %s", node.Password)
	}
	if node.Tag != "HY2 Node" {
		t.Errorf("tag = %s", node.Tag)
	}
}

func TestParseHy2_Hysteria2Prefix(t *testing.T) {
	link := "hysteria2://pass@host.com:443#test"
	node := ParseHy2(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.Type != "hysteria2" {
		t.Errorf("type = %s", node.Type)
	}
}

func TestParseHy2_WithObfs(t *testing.T) {
	link := "hy2://pass@host.com:443?obfs=salamander&obfs-password=obfspass#Obfs"
	node := ParseHy2(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.Transport == nil {
		t.Fatal("transport should be set for obfs")
	}
	if node.Transport["type"] != "salamander" {
		t.Errorf("obfs type = %v", node.Transport["type"])
	}
	if node.Transport["password"] != "obfspass" {
		t.Errorf("obfs password = %v", node.Transport["password"])
	}
}

// ── ParseTuic ──

func TestParseTuic_Valid(t *testing.T) {
	link := "tuic://uuid-tuic:tuicpass@tuic.example.com:443?sni=tuic.example.com#TUIC%20Node"
	node := ParseTuic(link)
	if node == nil {
		t.Fatal("nil")
	}
	if node.Type != "tuic" {
		t.Errorf("type = %s", node.Type)
	}
	if node.UUID != "uuid-tuic" {
		t.Errorf("uuid = %s", node.UUID)
	}
	if node.Password != "tuicpass" {
		t.Errorf("password = %s", node.Password)
	}
	if node.Tag != "TUIC Node" {
		t.Errorf("tag = %s", node.Tag)
	}
	if node.TLS == nil {
		t.Fatal("TLS should be set")
	}
}

// ── ParseLinks ──

func TestParseLinks_MultipleProtocols(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass"))
	ssLink := "ss://" + userinfo + "@1.2.3.4:8388#SS"

	trojanLink := "trojan://pass@host.com:443#Trojan"

	text := ssLink + "\n" + trojanLink + "\n"
	nodes := ParseLinks(text)
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Type != "shadowsocks" {
		t.Errorf("first node type = %s", nodes[0].Type)
	}
	if nodes[1].Type != "trojan" {
		t.Errorf("second node type = %s", nodes[1].Type)
	}
}

func TestParseLinks_SkipsComments(t *testing.T) {
	text := "# This is a comment\ntrojan://pass@host.com:443#Node\n\n"
	nodes := ParseLinks(text)
	if len(nodes) != 1 {
		t.Errorf("expected 1 node (skip comment), got %d", len(nodes))
	}
}

func TestParseLinks_SkipsEmpty(t *testing.T) {
	nodes := ParseLinks("\n\n  \n")
	if len(nodes) != 0 {
		t.Errorf("empty input should return 0 nodes, got %d", len(nodes))
	}
}

func TestParseLinks_UnknownProtocol(t *testing.T) {
	nodes := ParseLinks("http://example.com\n")
	if len(nodes) != 0 {
		t.Errorf("unknown protocol should be skipped, got %d", len(nodes))
	}
}

// ── ParseSubscription ──

func TestParseSubscription_PlainLinks(t *testing.T) {
	text := "trojan://pass@host.com:443#Node1\n"
	nodes := ParseSubscription(text)
	if len(nodes) != 1 {
		t.Errorf("expected 1, got %d", len(nodes))
	}
}

func TestParseSubscription_Base64Encoded(t *testing.T) {
	plain := "trojan://pass@host.com:443#Node1\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	nodes := ParseSubscription(encoded)
	if len(nodes) != 1 {
		t.Errorf("expected 1 from base64, got %d", len(nodes))
	}
}

// ── splitHostPort ──

func TestSplitHostPort_IPv4(t *testing.T) {
	host, port := splitHostPort("1.2.3.4:8080")
	if host != "1.2.3.4" || port != "8080" {
		t.Errorf("got %s:%s", host, port)
	}
}

func TestSplitHostPort_IPv6(t *testing.T) {
	host, port := splitHostPort("[::1]:8080")
	if host != "::1" || port != "8080" {
		t.Errorf("got %s:%s", host, port)
	}
}

func TestSplitHostPort_NoPort(t *testing.T) {
	host, port := splitHostPort("hostname")
	if host != "hostname" || port != "" {
		t.Errorf("got %s:%s", host, port)
	}
}
