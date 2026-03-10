package api

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/parsers"
	"macflow/internal/state"
)

// GET /api/subscriptions
func (s *Server) handleSubscriptions(c *gin.Context) {
	st := s.store.Read()
	result := make([]gin.H, 0, len(st.Subscriptions))
	for _, sub := range st.Subscriptions {
		nodeCount := 0
		for _, n := range st.Nodes {
			if n.Source == sub.ID && n.SourceType == "subscription" {
				nodeCount++
			}
		}
		result = append(result, gin.H{
			"id":         sub.ID,
			"name":       sub.Name,
			"url":        sub.URL,
			"last_sync":  sub.LastSync,
			"headers":    sub.Headers,
			"node_count": nodeCount,
		})
	}
	c.JSON(200, result)
}

// POST /api/subscriptions
func (s *Server) handleSubCreate(c *gin.Context) {
	var req struct {
		Name    string            `json:"name" binding:"required,max=256"`
		URL     string            `json:"url" binding:"required,max=2048"`
		Headers map[string]string `json:"headers,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		c.JSON(400, gin.H{"detail": "url 必须以 http:// 或 https:// 开头"})
		return
	}

	id := generateID()

	if err := s.store.Update(func(st *state.State) {
		st.Subscriptions = append(st.Subscriptions, state.Subscription{
			ID:      id,
			Name:    req.Name,
			URL:     req.URL,
			Headers: req.Headers,
		})
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	s.audit.Log("sub_create", fmt.Sprintf("name=%s", req.Name))
	c.JSON(200, gin.H{"ok": true, "id": id})
}

// PUT /api/subscriptions/:sid
func (s *Server) handleSubUpdate(c *gin.Context) {
	sid := c.Param("sid")
	var req struct {
		Name    *string            `json:"name,omitempty"`
		URL     *string            `json:"url,omitempty"`
		Headers map[string]string  `json:"headers,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	if req.URL != nil {
		u, err := url.Parse(*req.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			c.JSON(400, gin.H{"detail": "url 无效"})
			return
		}
	}

	found := false
	if err := s.store.Update(func(st *state.State) {
		for i := range st.Subscriptions {
			if st.Subscriptions[i].ID == sid {
				found = true
				if req.Name != nil {
					st.Subscriptions[i].Name = *req.Name
				}
				if req.URL != nil {
					st.Subscriptions[i].URL = *req.URL
				}
				if req.Headers != nil {
					st.Subscriptions[i].Headers = req.Headers
				}
				break
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "订阅不存在"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// DELETE /api/subscriptions/:sid
func (s *Server) handleSubDelete(c *gin.Context) {
	sid := c.Param("sid")

	found := false
	if err := s.store.Update(func(st *state.State) {
		newSubs := make([]state.Subscription, 0, len(st.Subscriptions))
		for _, sub := range st.Subscriptions {
			if sub.ID == sid {
				found = true
			} else {
				newSubs = append(newSubs, sub)
			}
		}
		st.Subscriptions = newSubs

		// Cascade: delete nodes from this subscription
		newNodes := make([]state.Node, 0, len(st.Nodes))
		for _, n := range st.Nodes {
			if !(n.Source == sid && n.SourceType == "subscription") {
				newNodes = append(newNodes, n)
			}
		}
		st.Nodes = newNodes
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "订阅不存在"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("sub_delete", fmt.Sprintf("sid=%s (cascade)", sid))
	c.JSON(200, gin.H{"ok": true, "runtime": runtime})
}

// POST /api/subscriptions/:sid/sync
func (s *Server) handleSubSync(c *gin.Context) {
	sid := c.Param("sid")
	st := s.store.Read()

	var sub *state.Subscription
	for i := range st.Subscriptions {
		if st.Subscriptions[i].ID == sid {
			sub = &st.Subscriptions[i]
			break
		}
	}
	if sub == nil {
		c.JSON(404, gin.H{"detail": "订阅不存在"})
		return
	}

	// SSRF protection
	if err := validateURLSafe(sub.URL); err != nil {
		c.JSON(400, gin.H{"detail": fmt.Sprintf("URL 安全检查失败: %v", err)})
		return
	}

	// Fetch subscription content
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", sub.URL, nil)
	req.Header.Set("User-Agent", "clash")
	for k, v := range sub.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(400, gin.H{"detail": fmt.Sprintf("获取订阅失败: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.JSON(400, gin.H{"detail": fmt.Sprintf("订阅返回 HTTP %d", resp.StatusCode)})
		return
	}

	// Limit to 10MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		c.JSON(400, gin.H{"detail": "读取订阅内容失败"})
		return
	}

	nodes := parsers.ParseSubscription(string(body))
	if len(nodes) == 0 {
		c.JSON(400, gin.H{"detail": "未解析到有效节点"})
		return
	}

	// Tag nodes with source info
	for i := range nodes {
		nodes[i].Source = sid
		nodes[i].SourceType = "subscription"
		nodes[i].Enabled = true
	}

	// Replace all nodes from this subscription
	count := 0
	if err := s.store.Update(func(st *state.State) {
		newNodes := make([]state.Node, 0, len(st.Nodes))
		for _, n := range st.Nodes {
			if !(n.Source == sid && n.SourceType == "subscription") {
				newNodes = append(newNodes, n)
			}
		}
		newNodes = append(newNodes, nodes...)
		st.Nodes = newNodes
		count = len(nodes)

		for i := range st.Subscriptions {
			if st.Subscriptions[i].ID == sid {
				st.Subscriptions[i].LastSync = time.Now().Unix()
				break
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("sub_sync", fmt.Sprintf("sid=%s count=%d", sid, count))
	c.JSON(200, gin.H{"ok": true, "count": count, "runtime": runtime})
}

// validateURLSafe performs SSRF protection: reject private/loopback IPs.
func validateURLSafe(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("无效 URL")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("缺少主机名")
	}

	// Resolve hostname
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("DNS 解析失败: %s", host)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("目标 IP %s 是内网地址", ipStr)
		}
	}

	return nil
}
