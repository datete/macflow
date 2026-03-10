package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/singbox"
)

// ── Egress detection helpers ──

var egressLock sync.Mutex

// egressService is one of the IP-check services.
type egressService struct {
	URL    string
	Format string // "json" or "text"
}

var egressServices = []egressService{
	{URL: "https://api.ipify.org?format=json", Format: "json"},
	{URL: "https://ifconfig.me/ip", Format: "text"},
	{URL: "https://icanhazip.com", Format: "text"},
}

type egressResult struct {
	Service  string `json:"service"`
	IP       string `json:"ip"`
	OK       bool   `json:"ok"`
	ViaProxy bool   `json:"via_proxy"`
	Error    string `json:"error,omitempty"`
}

// testEgressIP probes multiple services to detect the egress IP.
func testEgressIP(useProxy bool) []egressResult {
	proxy := ""
	if useProxy {
		proxy = "http://127.0.0.1:1080"
	}

	var wg sync.WaitGroup
	results := make([]egressResult, len(egressServices))

	for i, svc := range egressServices {
		wg.Add(1)
		go func(idx int, s egressService) {
			defer wg.Done()
			r := egressResult{Service: s.URL, ViaProxy: useProxy}

			client := &http.Client{Timeout: 8 * time.Second}
			if proxy != "" {
				proxyURL, _ := url.Parse(proxy)
				client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			}

			resp, err := client.Get(s.URL)
			if err != nil {
				r.Error = err.Error()
				results[idx] = r
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
			if err != nil {
				r.Error = err.Error()
				results[idx] = r
				return
			}

			ip := ""
			if s.Format == "json" {
				var data map[string]interface{}
				if json.Unmarshal(body, &data) == nil {
					if v, ok := data["ip"].(string); ok {
						ip = v
					}
				}
			} else {
				ip = strings.TrimSpace(string(body))
			}

			if net.ParseIP(ip) != nil {
				r.IP = ip
				r.OK = true
			} else {
				r.Error = "invalid IP response"
			}
			results[idx] = r
		}(i, svc)
	}

	wg.Wait()
	return results
}

// testEgressForSelector switches Clash selector, probes, then restores.
func testEgressForSelector(tag string) []egressResult {
	egressLock.Lock()
	defer egressLock.Unlock()

	// Get current selector state
	origTag := ""
	if now, _, err := singbox.GetSelectorState(); err == nil {
		origTag = now
	}

	// Switch if needed
	if tag != origTag && tag != "" {
		singbox.SetSelector(tag)
		time.Sleep(250 * time.Millisecond)
	}

	results := testEgressIP(true)

	// Restore
	if origTag != "" && origTag != tag {
		singbox.SetSelector(origTag)
	}

	return results
}

// summarizeEgress extracts unique IPs and consistency info.
func summarizeEgress(results []egressResult) (string, bool, []string) {
	seen := map[string]bool{}
	for _, r := range results {
		if r.OK && r.IP != "" {
			seen[r.IP] = true
		}
	}
	var uniqueIPs []string
	for ip := range seen {
		uniqueIPs = append(uniqueIPs, ip)
	}
	consistent := len(uniqueIPs) == 1
	detectedIP := ""
	if len(uniqueIPs) > 0 {
		detectedIP = uniqueIPs[0]
	}
	return detectedIP, consistent, uniqueIPs
}

// lookupIPGeo queries GeoIP info for an IP.
func lookupIPGeo(ip string) map[string]interface{} {
	if ip == "" {
		return nil
	}
	urls := []string{
		fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN", ip),
		fmt.Sprintf("https://ipwho.is/%s", ip),
	}
	client := &http.Client{Timeout: 5 * time.Second}

	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
		if err != nil {
			continue
		}
		var data map[string]interface{}
		if json.Unmarshal(body, &data) == nil {
			return data
		}
	}
	return nil
}

// handleEgressNode checks egress IP for a specific node.
//
// GET /api/egress/node/:tag
func (s *Server) handleEgressNode(c *gin.Context) {
	tag := c.Param("tag")
	st := s.store.Read()

	var node *nodeRef
	for _, n := range st.Nodes {
		if n.Tag == tag {
			node = &nodeRef{Tag: n.Tag, Server: n.Server, Enabled: n.Enabled}
			break
		}
	}
	if node == nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "节点不存在"})
		return
	}
	if !node.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "节点已禁用"})
		return
	}

	results := testEgressForSelector(tag)
	detectedIP, consistent, uniqueIPs := summarizeEgress(results)

	resp := gin.H{
		"tag":         tag,
		"node_server": node.Server,
		"results":     results,
		"detected_ip": detectedIP,
		"consistent":  consistent,
		"unique_ips":  uniqueIPs,
		"tested_at":   time.Now().Unix(),
		"proxied":     true,
		"note":        fmt.Sprintf("通过 selector=%s 检测", tag),
	}

	// GeoIP lookup
	if geo := lookupIPGeo(detectedIP); geo != nil {
		for _, k := range []string{"country", "country_code", "city", "isp"} {
			if v, ok := geo[k]; ok {
				resp[k] = v
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

// handleEgressDevice checks egress IP for a device via its bound node.
//
// GET /api/egress/device/:mac
func (s *Server) handleEgressDevice(c *gin.Context) {
	mac := c.Param("mac")
	st := s.store.Read()

	macNorm := normalizeMac(mac)
	var deviceName, nodeTag, nodeServer string
	found := false

	for _, d := range st.Devices {
		if normalizeMac(d.MAC) == macNorm {
			found = true
			deviceName = d.Name
			nodeTag = d.NodeTag
			break
		}
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"detail": "设备不存在"})
		return
	}

	var results []egressResult
	proxied := false
	note := ""

	if nodeTag == "direct" || nodeTag == "" {
		results = testEgressIP(false)
		note = "设备直连（无代理）"
	} else {
		// Find node
		for _, n := range st.Nodes {
			if n.Tag == nodeTag && n.Enabled {
				nodeServer = n.Server
				break
			}
		}
		if nodeServer != "" {
			results = testEgressForSelector(nodeTag)
			proxied = true
			note = fmt.Sprintf("设备绑定 %s，通过 selector=%s 检测", nodeTag, nodeTag)
		} else {
			results = testEgressIP(false)
			note = "绑定节点不可用，使用直连检测"
		}
	}

	detectedIP, consistent, uniqueIPs := summarizeEgress(results)

	resp := gin.H{
		"mac":          mac,
		"device_name":  deviceName,
		"node_tag":     nodeTag,
		"node_server":  nodeServer,
		"results":      results,
		"detected_ip":  detectedIP,
		"consistent":   consistent,
		"unique_ips":   uniqueIPs,
		"tested_at":    time.Now().Unix(),
		"proxied":      proxied,
		"note":         note,
	}

	if geo := lookupIPGeo(detectedIP); geo != nil {
		for _, k := range []string{"country", "country_code", "city", "isp"} {
			if v, ok := geo[k]; ok {
				resp[k] = v
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

// handleEgressRouter checks the router's own egress IP via proxy.
//
// GET /api/egress/router
func (s *Server) handleEgressRouter(c *gin.Context) {
	results := testEgressIP(true)
	detectedIP, consistent, uniqueIPs := summarizeEgress(results)

	resp := gin.H{
		"results":     results,
		"detected_ip": detectedIP,
		"consistent":  consistent,
		"unique_ips":  uniqueIPs,
		"tested_at":   time.Now().Unix(),
		"proxied":     true,
		"note":        "通过 mixed 入站代理出口检测",
	}

	if geo := lookupIPGeo(detectedIP); geo != nil {
		for _, k := range []string{"country", "country_code", "city", "isp"} {
			if v, ok := geo[k]; ok {
				resp[k] = v
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

// nodeRef is a lightweight node reference.
type nodeRef struct {
	Tag     string
	Server  string
	Enabled bool
}
