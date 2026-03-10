package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/state"
)

// GET /api/sources
func (s *Server) handleSources(c *gin.Context) {
	st := s.store.Read()
	result := make([]gin.H, 0, len(st.XUISourceList))
	for _, src := range st.XUISourceList {
		nodeCount := 0
		for _, n := range st.Nodes {
			if n.Source == src.ID && n.SourceType == "3xui" {
				nodeCount++
			}
		}
		result = append(result, gin.H{
			"id":         src.ID,
			"name":       src.Name,
			"base_url":   src.BaseURL,
			"username":   src.Username,
			"password":   "***",
			"enabled":    src.Enabled,
			"node_count": nodeCount,
		})
	}
	c.JSON(200, result)
}

// POST /api/sources
func (s *Server) handleSourceCreate(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required,max=256"`
		BaseURL  string `json:"base_url" binding:"required,max=2048"`
		Username string `json:"username" binding:"required,max=256"`
		Password string `json:"password" binding:"required,max=512"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误: " + err.Error()})
		return
	}

	// Validate URL
	req.BaseURL = strings.TrimRight(req.BaseURL, "/")
	u, err := url.Parse(req.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		c.JSON(400, gin.H{"detail": "base_url 必须以 http:// 或 https:// 开头"})
		return
	}

	id := generateID()

	if err := s.store.Update(func(st *state.State) {
		st.XUISourceList = append(st.XUISourceList, state.XUISource{
			ID:       id,
			Name:     req.Name,
			BaseURL:  req.BaseURL,
			Username: req.Username,
			Password: req.Password,
			Enabled:  true,
		})
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	s.audit.Log("source_create", fmt.Sprintf("name=%s", req.Name))
	c.JSON(200, gin.H{"ok": true, "id": id})
}

// PUT /api/sources/:sid
func (s *Server) handleSourceUpdate(c *gin.Context) {
	sid := c.Param("sid")
	var req struct {
		Name     *string `json:"name,omitempty"`
		BaseURL  *string `json:"base_url,omitempty"`
		Username *string `json:"username,omitempty"`
		Password *string `json:"password,omitempty"`
		Enabled  *bool   `json:"enabled,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	if req.BaseURL != nil {
		trimmed := strings.TrimRight(*req.BaseURL, "/")
		u, err := url.Parse(trimmed)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			c.JSON(400, gin.H{"detail": "base_url 无效"})
			return
		}
		req.BaseURL = &trimmed
	}

	found := false
	if err := s.store.Update(func(st *state.State) {
		for i := range st.XUISourceList {
			if st.XUISourceList[i].ID == sid {
				found = true
				if req.Name != nil {
					st.XUISourceList[i].Name = *req.Name
				}
				if req.BaseURL != nil {
					st.XUISourceList[i].BaseURL = *req.BaseURL
				}
				if req.Username != nil {
					st.XUISourceList[i].Username = *req.Username
				}
				if req.Password != nil {
					st.XUISourceList[i].Password = *req.Password
				}
				if req.Enabled != nil {
					st.XUISourceList[i].Enabled = *req.Enabled
				}
				break
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "源不存在"})
		return
	}

	s.audit.Log("source_update", fmt.Sprintf("sid=%s", sid))
	c.JSON(200, gin.H{"ok": true})
}

// DELETE /api/sources/:sid
func (s *Server) handleSourceDelete(c *gin.Context) {
	sid := c.Param("sid")

	found := false
	if err := s.store.Update(func(st *state.State) {
		// Remove source
		newSources := make([]state.XUISource, 0, len(st.XUISourceList))
		for _, src := range st.XUISourceList {
			if src.ID == sid {
				found = true
			} else {
				newSources = append(newSources, src)
			}
		}
		st.XUISourceList = newSources

		// Cascade: delete nodes from this source
		newNodes := make([]state.Node, 0, len(st.Nodes))
		for _, n := range st.Nodes {
			if !(n.Source == sid && n.SourceType == "3xui") {
				newNodes = append(newNodes, n)
			}
		}
		st.Nodes = newNodes
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "源不存在"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("source_delete", fmt.Sprintf("sid=%s (cascade)", sid))
	c.JSON(200, gin.H{"ok": true, "runtime": runtime})
}

// POST /api/sources/:sid/sync
func (s *Server) handleSourceSync(c *gin.Context) {
	sid := c.Param("sid")
	st := s.store.Read()

	var src *state.XUISource
	for i := range st.XUISourceList {
		if st.XUISourceList[i].ID == sid {
			src = &st.XUISourceList[i]
			break
		}
	}
	if src == nil {
		c.JSON(404, gin.H{"detail": "源不存在"})
		return
	}

	// Sync from 3x-UI panel
	nodes, err := sync3xUI(src.BaseURL, src.Username, src.Password)
	if err != nil {
		// Record error
		s.store.Update(func(st *state.State) {
			for i := range st.XUISourceList {
				if st.XUISourceList[i].ID == sid {
					st.XUISourceList[i].LastError = err.Error()
					break
				}
			}
		})
		c.JSON(400, gin.H{"detail": fmt.Sprintf("同步失败: %v", err)})
		return
	}

	// Replace loopback server with panel host
	panelHost := extractHost(src.BaseURL)
	for i := range nodes {
		if isLoopback(nodes[i].Server) && panelHost != "" {
			nodes[i].Server = panelHost
		}
		nodes[i].Source = sid
		nodes[i].SourceType = "3xui"
		nodes[i].Enabled = true
	}

	// Deduplicate and apply
	added, skipped := 0, 0
	if err := s.store.Update(func(st *state.State) {
		// Collect existing tags from other sources
		existingTags := make(map[string]bool)
		var keep []state.Node
		for _, n := range st.Nodes {
			if n.Source == sid && n.SourceType == "3xui" {
				continue // remove old nodes from this source
			}
			keep = append(keep, n)
			existingTags[n.Tag] = true
		}

		for _, n := range nodes {
			if existingTags[n.Tag] {
				skipped++
				continue
			}
			keep = append(keep, n)
			existingTags[n.Tag] = true
			added++
		}
		st.Nodes = keep

		// Update source timestamp
		for i := range st.XUISourceList {
			if st.XUISourceList[i].ID == sid {
				st.XUISourceList[i].LastSync = time.Now().Unix()
				st.XUISourceList[i].LastError = ""
				break
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("source_sync", fmt.Sprintf("sid=%s added=%d", sid, added))
	c.JSON(200, gin.H{
		"ok":                true,
		"count":             added,
		"added":             added,
		"skipped":           skipped,
		"total_from_source": len(nodes),
		"runtime":           runtime,
	})
}

// sync3xUI calls a 3x-UI panel API and returns parsed nodes.
func sync3xUI(baseURL, username, password string) ([]state.Node, error) {
	// Login
	client := &http.Client{Timeout: 15 * time.Second}

	loginURL := baseURL + "/login"
	loginBody := fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
	resp, err := client.Post(loginURL, "application/json", strings.NewReader(loginBody))
	if err != nil {
		return nil, fmt.Errorf("连接面板失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("登录失败, HTTP %d", resp.StatusCode)
	}

	// Get cookies for session
	cookies := resp.Cookies()

	// Fetch inbounds
	req, _ := http.NewRequest("GET", baseURL+"/panel/api/inbounds/list", nil)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp2, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取入站失败: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		return nil, fmt.Errorf("获取入站失败, HTTP %d", resp2.StatusCode)
	}

	// TODO: Parse 3x-UI inbound response JSON into nodes
	// This requires understanding the 3x-UI API format which varies by version.
	// For now, return empty list (actual parsing logic will be ported from Python).
	return []state.Node{}, nil
}

// ── Helpers ──

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}
