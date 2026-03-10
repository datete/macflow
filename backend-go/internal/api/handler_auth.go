package api

import (
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/auth"
)

// ── Static pages ──

func (s *Server) handleIndex(c *gin.Context) {
	c.File(s.cfg.WebDir + "/index.html")
}

func (s *Server) handleCaptive(c *gin.Context) {
	c.File(s.cfg.WebDir + "/captive.html")
}

// ── Auth endpoints ──

// extractToken retrieves the auth token from header, cookie, or bearer.
func extractToken(c *gin.Context) string {
	if t := c.GetHeader("X-Auth-Token"); t != "" {
		return t
	}
	if t, err := c.Cookie("macflow_token"); err == nil && t != "" {
		return t
	}
	if h := c.GetHeader("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
		return h[7:]
	}
	return ""
}

// GET /api/auth/status
func (s *Server) handleAuthStatus(c *gin.Context) {
	cfg := s.auth.LoadAuth()
	token := extractToken(c)
	role := s.auth.GetSessionRole(token)
	if role == "" && !cfg.AuthEnabled {
		role = "admin"
	}
	c.JSON(200, gin.H{
		"auth_enabled":     cfg.AuthEnabled,
		"password_set":     cfg.PasswordHash != "",
		"valid_session":    s.auth.ValidateSession(token),
		"role":             role,
		"readonly_enabled": cfg.ReadonlyEnabled,
	})
}

// POST /api/auth/login
func (s *Server) handleAuthLogin(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required,max=512"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	clientIP := c.ClientIP()
	if !s.auth.CheckRateLimit(clientIP) {
		c.JSON(429, gin.H{"detail": "登录尝试过于频繁，请稍后再试"})
		return
	}

	cfg := s.auth.LoadAuth()
	if !cfg.AuthEnabled {
		c.JSON(200, gin.H{"ok": true, "message": "认证未启用", "token": "", "role": "admin"})
		return
	}

	// Try readonly password first (if enabled and set)
	if cfg.ReadonlyEnabled && cfg.ReadonlyPasswordHash != "" {
		if auth.VerifyPassword(req.Password, cfg.ReadonlyPasswordHash) {
			token, err := s.auth.CreateSession(clientIP, "readonly")
			if err != nil {
				c.JSON(500, gin.H{"detail": "创建会话失败"})
				return
			}
			c.SetCookie("macflow_token", token, int(auth.SessionTTL.Seconds()), "/", "", false, true)
			c.JSON(200, gin.H{"ok": true, "message": "登录成功（只读模式）", "token": token, "role": "readonly"})
			return
		}
	}

	// Try admin password
	if !auth.VerifyPassword(req.Password, cfg.PasswordHash) {
		s.auth.RecordAttempt(clientIP)
		c.JSON(401, gin.H{"detail": "密码错误"})
		return
	}

	token, err := s.auth.CreateSession(clientIP, "admin")
	if err != nil {
		c.JSON(500, gin.H{"detail": "创建会话失败"})
		return
	}

	c.SetCookie("macflow_token", token, int(auth.SessionTTL.Seconds()), "/", "", false, true)
	c.JSON(200, gin.H{"ok": true, "message": "登录成功", "token": token, "role": "admin"})
}

// POST /api/auth/logout
func (s *Server) handleAuthLogout(c *gin.Context) {
	token := extractToken(c)
	if token != "" {
		s.auth.DeleteSession(token)
	}
	c.SetCookie("macflow_token", "", -1, "/", "", false, true)
	c.JSON(200, gin.H{"ok": true, "message": "已登出"})
}

// POST /api/auth/setup
func (s *Server) handleAuthSetup(c *gin.Context) {
	var req struct {
		Password    string `json:"password" binding:"required,max=512"`
		NewPassword string `json:"new_password,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	cfg := s.auth.LoadAuth()

	var newPwd string

	if cfg.PasswordHash == "" {
		// First-time setup: password IS the new password
		newPwd = req.Password
	} else {
		// Change password: verify old, set new
		if !auth.VerifyPassword(req.Password, cfg.PasswordHash) {
			c.JSON(401, gin.H{"detail": "当前密码错误"})
			return
		}
		newPwd = req.NewPassword
		if newPwd == "" {
			newPwd = req.Password
		}
	}

	if len(newPwd) < 8 {
		c.JSON(400, gin.H{"detail": "密码长度不能少于8位"})
		return
	}

	hash, err := auth.HashPassword(newPwd)
	if err != nil {
		c.JSON(500, gin.H{"detail": "密码哈希失败"})
		return
	}

	cfg.PasswordHash = hash
	cfg.AuthEnabled = true
	if err := s.auth.SaveAuth(cfg); err != nil {
		c.JSON(500, gin.H{"detail": "保存认证配置失败"})
		return
	}

	// Clear all existing sessions
	s.auth.ClearSessions()

	// Create a new session for the user
	token, err := s.auth.CreateSession(c.ClientIP(), "admin")
	if err != nil {
		c.JSON(500, gin.H{"detail": "创建会话失败"})
		return
	}

	c.SetCookie("macflow_token", token, int(auth.SessionTTL.Seconds()), "/", "", false, true)
	s.audit.Log("auth_setup", "密码已设置")
	c.JSON(200, gin.H{"ok": true, "message": "密码已设置", "token": token, "role": "admin"})
}

// POST /api/auth/disable
func (s *Server) handleAuthDisable(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required,max=512"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	cfg := s.auth.LoadAuth()
	if !auth.VerifyPassword(req.Password, cfg.PasswordHash) {
		c.JSON(401, gin.H{"detail": "密码错误"})
		return
	}

	cfg.AuthEnabled = false
	if err := s.auth.SaveAuth(cfg); err != nil {
		c.JSON(500, gin.H{"detail": "保存配置失败"})
		return
	}

	s.auth.ClearSessions()
	s.audit.Log("auth_disable", "认证已关闭")
	c.JSON(200, gin.H{"ok": true, "message": "认证已关闭"})
}

// POST /api/auth/readonly — set or clear readonly password
//
// Body: {"password": "adminpwd", "readonly_password": "newpwd"}
// To disable: {"password": "adminpwd", "readonly_password": ""}
func (s *Server) handleAuthReadonly(c *gin.Context) {
	var req struct {
		Password         string `json:"password" binding:"required,max=512"`
		ReadonlyPassword string `json:"readonly_password" binding:"max=512"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"detail": "请求格式错误"})
		return
	}

	cfg := s.auth.LoadAuth()
	if !auth.VerifyPassword(req.Password, cfg.PasswordHash) {
		c.JSON(401, gin.H{"detail": "管理员密码错误"})
		return
	}

	if req.ReadonlyPassword == "" {
		// Disable readonly
		cfg.ReadonlyEnabled = false
		cfg.ReadonlyPasswordHash = ""
		if err := s.auth.SaveAuth(cfg); err != nil {
			c.JSON(500, gin.H{"detail": "保存失败"})
			return
		}
		s.audit.Log("auth_readonly", "只读密码已清除")
		c.JSON(200, gin.H{"ok": true, "message": "只读密码已清除", "readonly_enabled": false})
		return
	}

	if len(req.ReadonlyPassword) < 6 {
		c.JSON(400, gin.H{"detail": "只读密码不能少于6位"})
		return
	}
	hash, err := auth.HashPassword(req.ReadonlyPassword)
	if err != nil {
		c.JSON(500, gin.H{"detail": "密码哈希失败"})
		return
	}
	cfg.ReadonlyPasswordHash = hash
	cfg.ReadonlyEnabled = true
	if err := s.auth.SaveAuth(cfg); err != nil {
		c.JSON(500, gin.H{"detail": "保存失败"})
		return
	}
	s.audit.Log("auth_readonly", "只读密码已设置")
	c.JSON(200, gin.H{"ok": true, "message": "只读密码已设置", "readonly_enabled": true})
}

// GET /api/status
func (s *Server) handleStatus(c *gin.Context) {
	st := s.store.Read()
	_, alerts, overall, _ := s.monitor.GetState()

	activeAlerts, criticalAlerts := 0, 0
	for _, a := range alerts {
		if a.Status == "active" {
			activeAlerts++
			if a.Severity == "critical" {
				criticalAlerts++
			}
		}
	}

	enabledNodes, managedDevices := 0, 0
	for _, n := range st.Nodes {
		if n.Enabled {
			enabledNodes++
		}
	}
	for _, d := range st.Devices {
		if d.Managed {
			managedDevices++
		}
	}

	c.JSON(200, gin.H{
		"version":              "2.0.0",
		"enabled":              st.Enabled,
		"default_policy":       st.DefaultPolicy,
		"failure_policy":       st.FailurePolicy,
		"node_count":           len(st.Nodes),
		"node_enabled":         enabledNodes,
		"device_count":         len(st.Devices),
		"managed_count":        managedDevices,
		"source_count":         len(st.XUISourceList),
		"sub_count":            len(st.Subscriptions),
		"last_sync":            st.LastSync,
		"last_apply":           st.LastApply,
		"policy_version":       st.PolicyVersion,
		"rollback_version":     st.RollbackVersion,
		"overall_health":       overall,
		"active_alert_count":   activeAlerts,
		"critical_alert_count": criticalAlerts,
		"uptime":               time.Since(bootTime).Seconds(),
	})
}
