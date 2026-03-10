package api

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/health"
	"macflow/internal/parsers"
	"macflow/internal/state"
)

// GET /api/nodes
func (s *Server) handleNodes(c *gin.Context) {
	st := s.store.Read()
	nodes := make([]gin.H, 0, len(st.Nodes))
	for _, n := range st.Nodes {
		score, status := health.ComputeNodeHealthScore(n.Latency, n.SpeedMbps, n.HealthFails, n.Enabled)
		nodes = append(nodes, gin.H{
			"tag":            n.Tag,
			"type":           n.Type,
			"server":         n.Server,
			"server_port":    n.ServerPort,
			"enabled":        n.Enabled,
			"source":         n.Source,
			"source_type":    n.SourceType,
			"latency":        n.Latency,
			"speed_mbps":     n.SpeedMbps,
			"health_score":   score,
			"health_status":  status,
			"health_failures": n.HealthFails,
			"last_probe_at":  n.LastProbeAt,
		})
	}

	// Sort: healthy first, then by score desc
	sort.Slice(nodes, func(i, j int) bool {
		si, _ := nodes[i]["health_score"].(int)
		sj, _ := nodes[j]["health_score"].(int)
		return si > sj
	})

	c.JSON(200, nodes)
}

// POST /api/nodes/manual
func (s *Server) handleNodeManual(c *gin.Context) {
	var req struct {
		Type       string                 `json:"type" binding:"required"`
		Tag        string                 `json:"tag" binding:"required,max=256"`
		Server     string                 `json:"server" binding:"required,max=256"`
		ServerPort int                    `json:"server_port" binding:"required"`
		Password   string                 `json:"password,omitempty"`
		UUID       string                 `json:"uuid,omitempty"`
		Method     string                 `json:"method,omitempty"`
		Flow       string                 `json:"flow,omitempty"`
		Security   string                 `json:"security,omitempty"`
		Username   string                 `json:"username,omitempty"`
		Transport  map[string]interface{} `json:"transport,omitempty"`
		TLS        map[string]interface{} `json:"tls,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误: " + err.Error()})
		return
	}

	// Check tag uniqueness
	st := s.store.Read()
	for _, n := range st.Nodes {
		if n.Tag == req.Tag {
			c.JSON(400, gin.H{"detail": fmt.Sprintf("节点名称 '%s' 已存在", req.Tag)})
			return
		}
	}

	node := state.Node{
		Type:       req.Type,
		Tag:        req.Tag,
		Server:     req.Server,
		ServerPort: req.ServerPort,
		Password:   req.Password,
		UUID:       req.UUID,
		Method:     req.Method,
		Flow:       req.Flow,
		Security:   req.Security,
		Username:   req.Username,
		Transport:  req.Transport,
		TLS:        req.TLS,
		Source:     "manual",
		SourceType: "manual",
		Enabled:    true,
	}

	if err := s.store.Update(func(st *state.State) {
		st.Nodes = append(st.Nodes, node)
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("node_create", fmt.Sprintf("tag=%s type=%s", req.Tag, req.Type))
	c.JSON(200, gin.H{"ok": true, "tag": req.Tag, "runtime": runtime})
}

// POST /api/nodes/import-link/preview
func (s *Server) handleNodeImportPreview(c *gin.Context) {
	var req struct {
		Links string `json:"links" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	if len(req.Links) > 1024*1024 {
		c.JSON(400, gin.H{"detail": "链接内容过大（最大 1MB）"})
		return
	}

	nodes := parsers.ParseLinks(req.Links)
	result := make([]gin.H, 0, len(nodes))
	for _, n := range nodes {
		result = append(result, gin.H{
			"tag":         n.Tag,
			"type":        n.Type,
			"server":      n.Server,
			"server_port": n.ServerPort,
		})
	}
	c.JSON(200, gin.H{"nodes": result, "count": len(result)})
}

// POST /api/nodes/import-link
func (s *Server) handleNodeImportLink(c *gin.Context) {
	var req struct {
		Links string `json:"links" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	if len(req.Links) > 1024*1024 {
		c.JSON(400, gin.H{"detail": "链接内容过大"})
		return
	}

	nodes := parsers.ParseLinks(req.Links)
	if len(nodes) == 0 {
		c.JSON(400, gin.H{"detail": "未解析到有效链接"})
		return
	}

	// Deduplicate by (server, port)
	type endpoint struct {
		server string
		port   int
	}
	seen := make(map[endpoint]bool)
	var unique []state.Node
	for _, n := range nodes {
		ep := endpoint{n.Server, n.ServerPort}
		if !seen[ep] {
			seen[ep] = true
			unique = append(unique, n)
		}
	}

	added, skipped := 0, 0
	if err := s.store.Update(func(st *state.State) {
		existingTags := make(map[string]bool)
		for _, n := range st.Nodes {
			existingTags[n.Tag] = true
		}

		for _, n := range unique {
			// Handle tag conflicts
			tag := n.Tag
			for existingTags[tag] {
				tag = n.Tag + "-" + generateID()[:4]
			}
			n.Tag = tag
			n.Source = "link"
			n.SourceType = "link"
			n.Enabled = true
			st.Nodes = append(st.Nodes, n)
			existingTags[tag] = true
			added++
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}
	skipped = len(nodes) - len(unique)

	runtime := s.rt.HotApply(false)
	s.audit.Log("node_import", fmt.Sprintf("added=%d skipped=%d", added, skipped))
	c.JSON(200, gin.H{"ok": true, "added": added, "skipped": skipped, "runtime": runtime})
}

// POST /api/nodes/sync-all
func (s *Server) handleSyncAll(c *gin.Context) {
	st := s.store.Read()

	totalAdded := 0
	var errors []string

	for _, src := range st.XUISourceList {
		if !src.Enabled {
			continue
		}

		nodes, err := sync3xUI(src.BaseURL, src.Username, src.Password)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", src.Name, err))
			continue
		}

		// Replace loopback
		panelHost := extractHost(src.BaseURL)
		for i := range nodes {
			if isLoopback(nodes[i].Server) && panelHost != "" {
				nodes[i].Server = panelHost
			}
			nodes[i].Source = src.ID
			nodes[i].SourceType = "3xui"
			nodes[i].Enabled = true
		}

		added := 0
		s.store.Update(func(st *state.State) {
			existingTags := make(map[string]bool)
			var keep []state.Node
			for _, n := range st.Nodes {
				if n.Source == src.ID && n.SourceType == "3xui" {
					continue
				}
				keep = append(keep, n)
				existingTags[n.Tag] = true
			}
			for _, n := range nodes {
				if !existingTags[n.Tag] {
					keep = append(keep, n)
					existingTags[n.Tag] = true
					added++
				}
			}
			st.Nodes = keep

			for i := range st.XUISourceList {
				if st.XUISourceList[i].ID == src.ID {
					st.XUISourceList[i].LastSync = time.Now().Unix()
					st.XUISourceList[i].LastError = ""
					break
				}
			}
		})
		totalAdded += added
	}

	runtime := s.rt.HotApply(false)
	c.JSON(200, gin.H{
		"ok":      true,
		"total":   totalAdded,
		"errors":  errors,
		"runtime": runtime,
	})
}

// PUT /api/nodes/:tag
func (s *Server) handleNodeUpdate(c *gin.Context) {
	tag := c.Param("tag")
	var req struct {
		Type       *string                 `json:"type,omitempty"`
		Tag        *string                 `json:"tag,omitempty"`
		Server     *string                 `json:"server,omitempty"`
		ServerPort *int                    `json:"server_port,omitempty"`
		Password   *string                 `json:"password,omitempty"`
		UUID       *string                 `json:"uuid,omitempty"`
		Method     *string                 `json:"method,omitempty"`
		Flow       *string                 `json:"flow,omitempty"`
		Transport  map[string]interface{}  `json:"transport,omitempty"`
		TLS        map[string]interface{}  `json:"tls,omitempty"`
		Enabled    *bool                   `json:"enabled,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	found := false
	newTag := tag
	if err := s.store.Update(func(st *state.State) {
		for i := range st.Nodes {
			if st.Nodes[i].Tag != tag {
				continue
			}
			found = true
			if req.Type != nil {
				st.Nodes[i].Type = *req.Type
			}
			if req.Tag != nil {
				newTag = *req.Tag
				// Cascade update device bindings
				for j := range st.Devices {
					if st.Devices[j].NodeTag == tag {
						st.Devices[j].NodeTag = newTag
					}
				}
				st.Nodes[i].Tag = newTag
			}
			if req.Server != nil {
				st.Nodes[i].Server = *req.Server
			}
			if req.ServerPort != nil {
				st.Nodes[i].ServerPort = *req.ServerPort
			}
			if req.Password != nil {
				st.Nodes[i].Password = *req.Password
			}
			if req.UUID != nil {
				st.Nodes[i].UUID = *req.UUID
			}
			if req.Method != nil {
				st.Nodes[i].Method = *req.Method
			}
			if req.Flow != nil {
				st.Nodes[i].Flow = *req.Flow
			}
			if req.Transport != nil {
				st.Nodes[i].Transport = req.Transport
			}
			if req.TLS != nil {
				st.Nodes[i].TLS = req.TLS
			}
			if req.Enabled != nil {
				st.Nodes[i].Enabled = *req.Enabled
			}
			break
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "节点不存在"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("node_update", fmt.Sprintf("tag=%s", newTag))
	c.JSON(200, gin.H{"ok": true, "tag": newTag, "runtime": runtime})
}

// DELETE /api/nodes/:tag
func (s *Server) handleNodeDelete(c *gin.Context) {
	tag := c.Param("tag")

	found := false
	if err := s.store.Update(func(st *state.State) {
		newNodes := make([]state.Node, 0, len(st.Nodes))
		for _, n := range st.Nodes {
			if n.Tag == tag {
				found = true
			} else {
				newNodes = append(newNodes, n)
			}
		}
		st.Nodes = newNodes

		// Unbind devices
		for i := range st.Devices {
			if st.Devices[i].NodeTag == tag {
				st.Devices[i].NodeTag = ""
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "节点不存在"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("node_delete", tag)
	c.JSON(200, gin.H{"ok": true, "runtime": runtime})
}

// POST /api/nodes/batch
func (s *Server) handleNodeBatch(c *gin.Context) {
	var req struct {
		Tags   []string `json:"tags" binding:"required"`
		Action string   `json:"action" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	validActions := map[string]bool{"delete": true, "enable": true, "disable": true}
	if !validActions[req.Action] {
		c.JSON(400, gin.H{"detail": fmt.Sprintf("无效操作: %s", req.Action)})
		return
	}
	if len(req.Tags) == 0 {
		c.JSON(400, gin.H{"detail": "tags 不能为空"})
		return
	}

	tagSet := make(map[string]bool, len(req.Tags))
	for _, t := range req.Tags {
		tagSet[t] = true
	}

	affected := 0
	if err := s.store.Update(func(st *state.State) {
		switch req.Action {
		case "delete":
			newNodes := make([]state.Node, 0, len(st.Nodes))
			for _, n := range st.Nodes {
				if tagSet[n.Tag] {
					affected++
					// Unbind devices
					for i := range st.Devices {
						if st.Devices[i].NodeTag == n.Tag {
							st.Devices[i].NodeTag = ""
						}
					}
				} else {
					newNodes = append(newNodes, n)
				}
			}
			st.Nodes = newNodes

		case "enable", "disable":
			enabled := req.Action == "enable"
			for i := range st.Nodes {
				if tagSet[st.Nodes[i].Tag] {
					st.Nodes[i].Enabled = enabled
					affected++
				}
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("node_batch", fmt.Sprintf("action=%s affected=%d", req.Action, affected))
	c.JSON(200, gin.H{"ok": true, "action": req.Action, "affected": affected, "runtime": runtime})
}

// PUT /api/nodes/:tag/toggle
func (s *Server) handleNodeToggle(c *gin.Context) {
	tag := c.Param("tag")

	found := false
	var enabled bool
	if err := s.store.Update(func(st *state.State) {
		for i := range st.Nodes {
			if st.Nodes[i].Tag == tag {
				found = true
				st.Nodes[i].Enabled = !st.Nodes[i].Enabled
				enabled = st.Nodes[i].Enabled
				break
			}
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}

	if !found {
		c.JSON(404, gin.H{"detail": "节点不存在"})
		return
	}

	runtime := s.rt.HotApply(false)
	c.JSON(200, gin.H{"ok": true, "enabled": enabled, "runtime": runtime})
}

// nodeTagFromPart URL-decodes a tag path parameter.
func nodeTagFromPart(c *gin.Context) string {
	return strings.TrimSpace(c.Param("tag"))
}
