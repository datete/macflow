// Package parsers handles protocol link parsing (ss://, vmess://, vless://, etc.)
// and subscription content parsing.
//
// This is the Go equivalent of Python's parsers.py module.
package parsers

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"macflow/internal/state"
)

// ParseLinks parses multiple protocol links (one per line) into nodes.
func ParseLinks(text string) []state.Node {
	var nodes []state.Node
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var node *state.Node
		switch {
		case strings.HasPrefix(line, "ss://"):
			node = ParseSS(line)
		case strings.HasPrefix(line, "vmess://"):
			node = ParseVmess(line)
		case strings.HasPrefix(line, "vless://"):
			node = ParseVless(line)
		case strings.HasPrefix(line, "trojan://"):
			node = ParseTrojan(line)
		case strings.HasPrefix(line, "hy2://") || strings.HasPrefix(line, "hysteria2://"):
			node = ParseHy2(line)
		case strings.HasPrefix(line, "tuic://"):
			node = ParseTuic(line)
		}
		if node != nil {
			nodes = append(nodes, *node)
		}
	}
	return nodes
}

// ParseSubscription tries to parse subscription content as:
// 1. sing-box JSON config
// 2. base64-encoded links
// 3. plain text links
func ParseSubscription(text string) []state.Node {
	text = strings.TrimSpace(text)

	// Try sing-box JSON
	if strings.HasPrefix(text, "{") {
		var config struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(text), &config); err == nil && len(config.Outbounds) > 0 {
			var nodes []state.Node
			for _, raw := range config.Outbounds {
				var node state.Node
				if err := json.Unmarshal(raw, &node); err == nil && node.Tag != "" && node.Type != "" {
					nodes = append(nodes, node)
				}
			}
			if len(nodes) > 0 {
				return nodes
			}
		}
	}

	// Try base64 decode
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
		decodedStr := string(decoded)
		if strings.Contains(decodedStr, "://") {
			if nodes := ParseLinks(decodedStr); len(nodes) > 0 {
				return nodes
			}
		}
	}
	// Try base64 URL-safe
	if decoded, err := base64.URLEncoding.DecodeString(text); err == nil {
		decodedStr := string(decoded)
		if strings.Contains(decodedStr, "://") {
			if nodes := ParseLinks(decodedStr); len(nodes) > 0 {
				return nodes
			}
		}
	}

	// Plain text links
	return ParseLinks(text)
}

// ParseSS parses an ss:// shadowsocks link.
func ParseSS(link string) *state.Node {
	// Format: ss://base64(method:password)@host:port#tag
	// or:     ss://base64(method:password@host:port)#tag
	link = strings.TrimPrefix(link, "ss://")

	tag := ""
	if idx := strings.LastIndex(link, "#"); idx >= 0 {
		tag, _ = url.QueryUnescape(link[idx+1:])
		link = link[:idx]
	}

	// Try to decode the entire part as base64
	if decoded, err := base64.RawURLEncoding.DecodeString(link); err == nil {
		link = string(decoded)
	}

	// Split userinfo@host:port
	atIdx := strings.LastIndex(link, "@")
	if atIdx < 0 {
		return nil
	}
	userinfo := link[:atIdx]
	hostport := link[atIdx+1:]

	// Decode userinfo if base64
	if decoded, err := base64.RawURLEncoding.DecodeString(userinfo); err == nil {
		userinfo = string(decoded)
	}

	colonIdx := strings.Index(userinfo, ":")
	if colonIdx < 0 {
		return nil
	}
	method := userinfo[:colonIdx]
	password := userinfo[colonIdx+1:]

	host, portStr := splitHostPort(hostport)
	if host == "" {
		return nil
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		return nil
	}

	if tag == "" {
		tag = host + ":" + portStr
	}

	return &state.Node{
		Type:       "shadowsocks",
		Tag:        tag,
		Server:     host,
		ServerPort: port,
		Method:     method,
		Password:   password,
		Enabled:    true,
	}
}

// ParseVmess parses a vmess:// link (V2Ray JSON format).
func ParseVmess(link string) *state.Node {
	link = strings.TrimPrefix(link, "vmess://")
	decoded, err := base64.RawURLEncoding.DecodeString(link)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(link)
		if err != nil {
			return nil
		}
	}

	var v map[string]interface{}
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil
	}

	host, _ := v["add"].(string)
	portFloat, _ := v["port"].(float64)
	port := int(portFloat)
	if portStr, ok := v["port"].(string); ok {
		port, _ = strconv.Atoi(portStr)
	}
	uuid, _ := v["id"].(string)
	tag, _ := v["ps"].(string)

	if host == "" || port == 0 || uuid == "" {
		return nil
	}
	if tag == "" {
		tag = host
	}

	node := &state.Node{
		Type:       "vmess",
		Tag:        tag,
		Server:     host,
		ServerPort: port,
		UUID:       uuid,
		Enabled:    true,
	}

	// TLS
	tls, _ := v["tls"].(string)
	if tls == "tls" {
		sni, _ := v["sni"].(string)
		if sni == "" {
			sni = host
		}
		node.TLS = map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
		}
	}

	// Transport
	net, _ := v["net"].(string)
	switch net {
	case "ws":
		wsPath, _ := v["path"].(string)
		wsHost, _ := v["host"].(string)
		transport := map[string]interface{}{
			"type": "ws",
			"path": wsPath,
		}
		if wsHost != "" {
			transport["headers"] = map[string]interface{}{"Host": wsHost}
		}
		node.Transport = transport
	case "grpc":
		svcName, _ := v["path"].(string)
		node.Transport = map[string]interface{}{
			"type":         "grpc",
			"service_name": svcName,
		}
	}

	return node
}

// ParseVless parses a vless:// link.
func ParseVless(link string) *state.Node {
	link = strings.TrimPrefix(link, "vless://")

	tag := ""
	if idx := strings.LastIndex(link, "#"); idx >= 0 {
		tag, _ = url.QueryUnescape(link[idx+1:])
		link = link[:idx]
	}

	u, err := url.Parse("vless://" + link)
	if err != nil {
		return nil
	}

	uuid := u.User.Username()
	host := u.Hostname()
	portStr := u.Port()
	port, _ := strconv.Atoi(portStr)

	if host == "" || port == 0 || uuid == "" {
		return nil
	}
	if tag == "" {
		tag = host
	}

	params := u.Query()
	node := &state.Node{
		Type:       "vless",
		Tag:        tag,
		Server:     host,
		ServerPort: port,
		UUID:       uuid,
		Flow:       params.Get("flow"),
		Enabled:    true,
	}

	// TLS / Reality
	security := params.Get("security")
	if security == "tls" || security == "reality" {
		sni := params.Get("sni")
		if sni == "" {
			sni = host
		}
		tlsCfg := map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
		}
		if security == "reality" {
			tlsCfg["reality"] = map[string]interface{}{
				"enabled":    true,
				"public_key": params.Get("pbk"),
				"short_id":   params.Get("sid"),
			}
		}
		node.TLS = tlsCfg
	}

	// Transport
	tType := params.Get("type")
	switch tType {
	case "ws":
		transport := map[string]interface{}{
			"type": "ws",
			"path": params.Get("path"),
		}
		if h := params.Get("host"); h != "" {
			transport["headers"] = map[string]interface{}{"Host": h}
		}
		node.Transport = transport
	case "grpc":
		node.Transport = map[string]interface{}{
			"type":         "grpc",
			"service_name": params.Get("serviceName"),
		}
	}

	return node
}

// ParseTrojan parses a trojan:// link.
func ParseTrojan(link string) *state.Node {
	link = strings.TrimPrefix(link, "trojan://")

	tag := ""
	if idx := strings.LastIndex(link, "#"); idx >= 0 {
		tag, _ = url.QueryUnescape(link[idx+1:])
		link = link[:idx]
	}

	u, err := url.Parse("trojan://" + link)
	if err != nil {
		return nil
	}

	password := u.User.Username()
	host := u.Hostname()
	portStr := u.Port()
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	if host == "" || password == "" {
		return nil
	}
	if tag == "" {
		tag = host
	}

	sni := u.Query().Get("sni")
	if sni == "" {
		sni = host
	}

	node := &state.Node{
		Type:       "trojan",
		Tag:        tag,
		Server:     host,
		ServerPort: port,
		Password:   password,
		TLS: map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
		},
		Enabled: true,
	}

	tType := u.Query().Get("type")
	switch tType {
	case "ws":
		transport := map[string]interface{}{
			"type": "ws",
			"path": u.Query().Get("path"),
		}
		if h := u.Query().Get("host"); h != "" {
			transport["headers"] = map[string]interface{}{"Host": h}
		}
		node.Transport = transport
	case "grpc":
		node.Transport = map[string]interface{}{
			"type":         "grpc",
			"service_name": u.Query().Get("serviceName"),
		}
	}

	return node
}

// ParseHy2 parses a hy2:// or hysteria2:// link.
func ParseHy2(link string) *state.Node {
	link = strings.TrimPrefix(link, "hysteria2://")
	link = strings.TrimPrefix(link, "hy2://")

	tag := ""
	if idx := strings.LastIndex(link, "#"); idx >= 0 {
		tag, _ = url.QueryUnescape(link[idx+1:])
		link = link[:idx]
	}

	u, err := url.Parse("hy2://" + link)
	if err != nil {
		return nil
	}

	password := u.User.Username()
	host := u.Hostname()
	portStr := u.Port()
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	if host == "" {
		return nil
	}
	if tag == "" {
		tag = host
	}

	sni := u.Query().Get("sni")
	if sni == "" {
		sni = host
	}

	node := &state.Node{
		Type:       "hysteria2",
		Tag:        tag,
		Server:     host,
		ServerPort: port,
		Password:   password,
		TLS: map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
		},
		Enabled: true,
	}

	if obfs := u.Query().Get("obfs"); obfs != "" {
		node.Transport = map[string]interface{}{
			"type":     obfs,
			"password": u.Query().Get("obfs-password"),
		}
	}

	return node
}

// ParseTuic parses a tuic:// link.
func ParseTuic(link string) *state.Node {
	link = strings.TrimPrefix(link, "tuic://")

	tag := ""
	if idx := strings.LastIndex(link, "#"); idx >= 0 {
		tag, _ = url.QueryUnescape(link[idx+1:])
		link = link[:idx]
	}

	u, err := url.Parse("tuic://" + link)
	if err != nil {
		return nil
	}

	uuid := u.User.Username()
	password, _ := u.User.Password()
	host := u.Hostname()
	portStr := u.Port()
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	if host == "" || uuid == "" {
		return nil
	}
	if tag == "" {
		tag = host
	}

	sni := u.Query().Get("sni")
	if sni == "" {
		sni = host
	}

	return &state.Node{
		Type:       "tuic",
		Tag:        tag,
		Server:     host,
		ServerPort: port,
		UUID:       uuid,
		Password:   password,
		TLS: map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
		},
		Enabled: true,
	}
}

// splitHostPort splits "host:port" handling IPv6 brackets.
func splitHostPort(s string) (string, string) {
	if strings.HasPrefix(s, "[") {
		// IPv6: [host]:port
		end := strings.Index(s, "]")
		if end < 0 {
			return "", ""
		}
		host := s[1:end]
		rest := s[end+1:]
		if strings.HasPrefix(rest, ":") {
			return host, rest[1:]
		}
		return host, ""
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}
