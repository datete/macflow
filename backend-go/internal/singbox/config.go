// Package singbox generates sing-box configuration files and
// interacts with the Clash API for selector/delay/traffic operations.
package singbox

import (
	"encoding/json"
	"fmt"
	"sort"

	"macflow/internal/health"
	"macflow/internal/state"
)

const (
	tunInterface = "singtun0"
	tunAddress   = "172.19.0.1/30"
)

// BuildConfig generates a complete sing-box JSON config from state.
func BuildConfig(st state.State) (map[string]interface{}, error) {
	// ── DNS ──
	dnsServers := st.DNS.Servers
	if len(dnsServers) == 0 {
		dnsServers = []string{"8.8.8.8", "1.1.1.1"}
	}

	var dnsServerList []map[string]interface{}
	for _, s := range dnsServers {
		dnsServerList = append(dnsServerList, map[string]interface{}{
			"tag":         fmt.Sprintf("dns-%s", s),
			"type":        "udp",
			"server":      s,
			"server_port": 53,
			"detour":      "proxy-select",
		})
	}
	dnsServerList = append(dnsServerList, map[string]interface{}{
		"tag":    "local-dns",
		"type":   "local",
		"detour": "direct-out",
	})

	dnsConfig := map[string]interface{}{
		"servers": dnsServerList,
		"rules": []map[string]interface{}{
			{"outbound": "any", "server": "local-dns"},
			{"clash_mode": "Direct", "server": "local-dns"},
		},
		"final": fmt.Sprintf("dns-%s", dnsServers[0]),
	}

	// ── Inbounds ──
	dnsPort := st.DNS.EnforceRedirectPort
	if dnsPort == 0 {
		dnsPort = 6053
	}

	inbounds := []map[string]interface{}{
		{
			"type":                        "tun",
			"tag":                         "tun-in",
			"interface_name":              tunInterface,
			"address":                     []string{tunAddress},
			"auto_route":                  false,
			"stack":                       "gvisor",
			"sniff":                       true,
			"sniff_override_destination":  true,
		},
		{
			"type":        "direct",
			"tag":         "dns-in",
			"listen":      "0.0.0.0",
			"listen_port": dnsPort,
		},
		{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": 1080,
		},
	}

	// ── Outbounds ──
	var enabledNodes []state.Node
	for _, n := range st.Nodes {
		if n.Enabled {
			enabledNodes = append(enabledNodes, n)
		}
	}

	// Sort by health score (best first)
	sort.Slice(enabledNodes, func(i, j int) bool {
		si, _ := health.ComputeNodeHealthScore(enabledNodes[i].Latency, enabledNodes[i].SpeedMbps, enabledNodes[i].HealthFails, true)
		sj, _ := health.ComputeNodeHealthScore(enabledNodes[j].Latency, enabledNodes[j].SpeedMbps, enabledNodes[j].HealthFails, true)
		return si > sj
	})

	var outbounds []map[string]interface{}
	var selectorOptions []string

	for _, n := range enabledNodes {
		ob := nodeToOutbound(n)
		if ob != nil {
			outbounds = append(outbounds, ob)
			selectorOptions = append(selectorOptions, n.Tag)
		}
	}

	// Add direct outbound
	outbounds = append(outbounds, map[string]interface{}{
		"type": "direct",
		"tag":  "direct-out",
	})

	// Selector
	selectorOptions = append(selectorOptions, "direct-out")
	defaultNode := "direct-out"
	if len(enabledNodes) > 0 {
		defaultNode = enabledNodes[0].Tag
	}

	selector := map[string]interface{}{
		"type":                           "selector",
		"tag":                            "proxy-select",
		"outbounds":                      selectorOptions,
		"default":                        defaultNode,
		"interrupt_exist_connections":     false,
	}
	// Prepend selector before other outbounds
	allOutbounds := []map[string]interface{}{selector}
	allOutbounds = append(allOutbounds, outbounds...)

	// ── Route ──
	routeRules := []map[string]interface{}{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
	}

	// Per-device routing rules
	// Build node->IPs mapping for source_ip_cidr routing
	nodeDevices := make(map[string][]string) // node_tag -> []ip_cidr
	for _, d := range st.Devices {
		if !d.Managed || d.NodeTag == "" || d.NodeTag == "direct" {
			continue
		}
		ip := d.IP
		if ip == "" {
			ip = d.LastIP
		}
		if ip == "" {
			continue
		}
		nodeDevices[d.NodeTag] = append(nodeDevices[d.NodeTag], ip+"/32")
	}

	for tag, cidrs := range nodeDevices {
		routeRules = append(routeRules, map[string]interface{}{
			"source_ip_cidr": cidrs,
			"outbound":       tag,
		})
	}

	route := map[string]interface{}{
		"auto_detect_interface": true,
		"rules":                 routeRules,
		"final":                 "proxy-select",
		"default_mark":          255,
	}

	// ── Full config ──
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level":     "info",
			"timestamp": true,
		},
		"dns":       dnsConfig,
		"inbounds":  inbounds,
		"outbounds": allOutbounds,
		"route":     route,
		"experimental": map[string]interface{}{
			"clash_api": map[string]interface{}{
				"external_controller": "127.0.0.1:9090",
				"external_ui":        "",
				"secret":             "",
			},
		},
	}

	return config, nil
}

// ConfigJSON returns the sing-box config as pretty-printed JSON.
func ConfigJSON(st state.State) ([]byte, error) {
	config, err := BuildConfig(st)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(config, "", "  ")
}

// nodeToOutbound converts a state.Node to a sing-box outbound dict.
func nodeToOutbound(n state.Node) map[string]interface{} {
	ob := map[string]interface{}{
		"type":        n.Type,
		"tag":         n.Tag,
		"server":      n.Server,
		"server_port": n.ServerPort,
	}

	switch n.Type {
	case "shadowsocks":
		ob["method"] = n.Method
		ob["password"] = n.Password

	case "vmess":
		ob["uuid"] = n.UUID
		ob["security"] = orDefault(n.Security, "auto")

	case "vless":
		ob["uuid"] = n.UUID
		if n.Flow != "" {
			ob["flow"] = n.Flow
		}

	case "trojan":
		ob["password"] = n.Password

	case "hysteria2":
		ob["password"] = n.Password
		if n.Transport != nil {
			if obfs, ok := n.Transport["type"].(string); ok && obfs != "" {
				ob["obfs"] = map[string]interface{}{
					"type":     obfs,
					"password": n.Transport["password"],
				}
			}
		}

	case "tuic":
		ob["uuid"] = n.UUID
		ob["password"] = n.Password

	case "socks", "http":
		if n.Username != "" {
			ob["username"] = n.Username
		}
		if n.Password != "" {
			ob["password"] = n.Password
		}

	default:
		// Unknown type, include raw fields
		if n.UUID != "" {
			ob["uuid"] = n.UUID
		}
		if n.Password != "" {
			ob["password"] = n.Password
		}
	}

	// TLS
	if n.TLS != nil {
		ob["tls"] = n.TLS
	}

	// Transport (ws, grpc, etc) — except for hysteria2 which uses it for obfs
	if n.Transport != nil && n.Type != "hysteria2" {
		ob["transport"] = n.Transport
	}

	return ob
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
