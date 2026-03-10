package api

import (
	"fmt"
	"net"

	"github.com/gin-gonic/gin"

	"macflow/internal/state"
)

// GET /api/settings
func (s *Server) handleSettings(c *gin.Context) {
	st := s.store.Read()
	c.JSON(200, gin.H{
		"enabled":        st.Enabled,
		"default_policy": st.DefaultPolicy,
		"failure_policy": st.FailurePolicy,
		"dns":            st.DNS,
	})
}

// PUT /api/settings
func (s *Server) handleSettingsUpdate(c *gin.Context) {
	var req struct {
		DefaultPolicy *string          `json:"default_policy,omitempty"`
		FailurePolicy *string          `json:"failure_policy,omitempty"`
		DNS           *state.DNSConfig `json:"dns,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	// Validate
	validPolicies := map[string]bool{"whitelist": true, "blacklist": true, "block": true, "allow": true}
	if req.DefaultPolicy != nil && !validPolicies[*req.DefaultPolicy] {
		c.JSON(400, gin.H{"detail": fmt.Sprintf("无效的 default_policy: %s", *req.DefaultPolicy)})
		return
	}
	validFailure := map[string]bool{"fail-close": true, "fail-open": true}
	if req.FailurePolicy != nil && !validFailure[*req.FailurePolicy] {
		c.JSON(400, gin.H{"detail": fmt.Sprintf("无效的 failure_policy: %s", *req.FailurePolicy)})
		return
	}
	if req.DNS != nil {
		for _, srv := range req.DNS.Servers {
			if net.ParseIP(srv) == nil {
				c.JSON(400, gin.H{"detail": fmt.Sprintf("无效的 DNS 服务器 IP: %s", srv)})
				return
			}
		}
	}

	if err := s.store.Update(func(st *state.State) {
		if req.DefaultPolicy != nil {
			st.DefaultPolicy = *req.DefaultPolicy
		}
		if req.FailurePolicy != nil {
			st.FailurePolicy = *req.FailurePolicy
		}
		if req.DNS != nil {
			st.DNS = *req.DNS
		}
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存设置失败"})
		return
	}

	runtime := s.rt.HotApply(false)
	s.audit.Log("settings_update", "设置已更新")
	c.JSON(200, gin.H{"ok": true, "runtime": runtime})
}

// POST /api/service/toggle
func (s *Server) handleToggle(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	if err := s.store.Update(func(st *state.State) {
		st.Enabled = req.Enabled
	}); err != nil {
		c.JSON(500, gin.H{"detail": "保存状态失败"})
		return
	}

	var runtime interface{}
	if req.Enabled {
		runtime = s.rt.HotApply(true)
	} else {
		runtime = s.rt.StopAll()
	}

	s.audit.Log("service_toggle", fmt.Sprintf("enabled=%v", req.Enabled))
	c.JSON(200, gin.H{"ok": true, "enabled": req.Enabled, "runtime": runtime})
}
