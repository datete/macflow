// Package api defines HTTP routes and handlers for the MACFlow REST API.
// Uses gin-gonic as the HTTP framework (lighter than echo, more features than stdlib).
package api

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/audit"
	"macflow/internal/auth"
	"macflow/internal/config"
	"macflow/internal/health"
	"macflow/internal/runtime"
	"macflow/internal/state"
)

// RuntimeService abstracts runtime operations for testability.
// Implemented by *runtime.Manager in production; mockable in tests.
type RuntimeService interface {
	HotApply(allowRestart bool) runtime.HotApplyResult
	StopAll() runtime.HotApplyResult
	GetFailCloseActive() bool
	GetFailCloseSince() int64
	GetFailCloseReason() string
}

// Server holds all dependencies needed by API handlers.
type Server struct {
	cfg     *config.Config
	store   *state.Store
	monitor *health.Monitor
	auth    *auth.Manager
	rt      RuntimeService
	audit   *audit.Logger
}

// NewRouter builds the complete HTTP router with all middleware and routes.
func NewRouter(cfg *config.Config, store *state.Store, monitor *health.Monitor) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	authMgr := auth.NewManager(cfg.DataDir)
	rtMgr := runtime.NewManager(store)
	auditLog := audit.NewLogger(cfg.DataDir)

	s := &Server{
		cfg:     cfg,
		store:   store,
		monitor: monitor,
		auth:    authMgr,
		rt:      rtMgr,
		audit:   auditLog,
	}

	// ── Middleware ──
	r.Use(s.corsMiddleware())
	r.Use(s.securityHeadersMiddleware())
	r.Use(s.authMiddleware())

	// ── Static pages ──
	r.GET("/", s.handleIndex)
	r.GET("/captive", s.handleCaptive)

	// ── API routes ──
	api := r.Group("/api")
	{
		// Auth
		api.GET("/auth/status", s.handleAuthStatus)
		api.POST("/auth/login", s.handleAuthLogin)
		api.POST("/auth/logout", s.handleAuthLogout)
		api.POST("/auth/setup", s.handleAuthSetup)
		api.POST("/auth/disable", s.handleAuthDisable)
		api.POST("/auth/readonly", s.handleAuthReadonly)

		// Status & Health
		api.GET("/status", s.handleStatus)
		api.GET("/health", s.handleHealth)
		api.GET("/alerts", s.handleAlerts)
		api.POST("/alerts/:id/ack", s.handleAlertAck)
		api.GET("/captive/status", s.handleCaptiveStatus)

		// Egress
		api.GET("/egress/node/:tag", s.handleEgressNode)
		api.GET("/egress/device/:mac", s.handleEgressDevice)
		api.GET("/egress/router", s.handleEgressRouter)

		// Settings
		api.GET("/settings", s.handleSettings)
		api.PUT("/settings", s.readonlyGuard(), s.handleSettingsUpdate)
		api.POST("/service/toggle", s.readonlyGuard(), s.handleToggle)

		// Sources (3x-UI)
		api.GET("/sources", s.handleSources)
		api.POST("/sources", s.readonlyGuard(), s.handleSourceCreate)
		api.PUT("/sources/:sid", s.readonlyGuard(), s.handleSourceUpdate)
		api.DELETE("/sources/:sid", s.readonlyGuard(), s.handleSourceDelete)
		api.POST("/sources/:sid/sync", s.readonlyGuard(), s.handleSourceSync)

		// Nodes
		api.GET("/nodes", s.handleNodes)
		api.POST("/nodes/manual", s.readonlyGuard(), s.handleNodeManual)
		api.POST("/nodes/import-link/preview", s.handleNodeImportPreview)
		api.POST("/nodes/import-link", s.readonlyGuard(), s.handleNodeImportLink)
		api.POST("/nodes/sync-all", s.readonlyGuard(), s.handleSyncAll)
		api.PUT("/nodes/:tag", s.readonlyGuard(), s.handleNodeUpdate)
		api.DELETE("/nodes/:tag", s.readonlyGuard(), s.handleNodeDelete)
		api.POST("/nodes/batch", s.readonlyGuard(), s.handleNodeBatch)
		api.PUT("/nodes/:tag/toggle", s.readonlyGuard(), s.handleNodeToggle)
		api.POST("/nodes/:tag/test", s.handleNodeTest)
		api.POST("/nodes/:tag/speedtest", s.handleNodeSpeedtest)
		api.POST("/nodes/health/refresh", s.readonlyGuard(), s.handleNodesHealthRefresh)

		// Subscriptions
		api.GET("/subscriptions", s.handleSubscriptions)
		api.POST("/subscriptions", s.readonlyGuard(), s.handleSubCreate)
		api.PUT("/subscriptions/:sid", s.readonlyGuard(), s.handleSubUpdate)
		api.DELETE("/subscriptions/:sid", s.readonlyGuard(), s.handleSubDelete)
		api.POST("/subscriptions/:sid/sync", s.readonlyGuard(), s.handleSubSync)

		// Devices
		api.GET("/devices", s.handleDevices)
		api.POST("/devices", s.readonlyGuard(), s.handleDeviceUpsert)
		api.POST("/devices/batch", s.readonlyGuard(), s.handleDeviceBatch)
		api.PUT("/devices/:mac/node", s.readonlyGuard(), s.handleDeviceSetNode)
		api.PUT("/devices/:mac/remark", s.readonlyGuard(), s.handleDeviceRemark)
		api.PUT("/devices/:mac/ip", s.readonlyGuard(), s.handleDeviceIP)
		api.DELETE("/devices/:mac", s.readonlyGuard(), s.handleDeviceDelete)

		// System
		api.GET("/system/info", s.handleSystemInfo)
		api.GET("/update/check", s.handleUpdateCheck)
		api.POST("/update/apply", s.readonlyGuard(), s.handleUpdateApply)

		// Traffic & Connections
		api.GET("/traffic/realtime", s.handleTrafficRealtime)
		api.GET("/traffic/connections", s.handleTrafficConnections)

		// SSE, Logs, DHCP, Apply
		api.GET("/events", s.handleSSE)
		api.GET("/logs", s.handleLogs)
		api.GET("/logs/tail", s.handleLogsTail)
		api.POST("/logs/clear", s.readonlyGuard(), s.handleLogsClear)
		api.GET("/dhcp/discover", s.handleDHCPDiscover)
		api.GET("/dhcp/leases", s.handleDHCPLeases)
		api.POST("/dhcp/bind", s.readonlyGuard(), s.handleDHCPBind)
		api.DELETE("/dhcp/bind/:mac", s.readonlyGuard(), s.handleDHCPBindDelete)
		api.POST("/apply", s.readonlyGuard(), s.handleApply)
		api.POST("/rollback", s.readonlyGuard(), s.handleRollback)

		// Metrics
		api.GET("/metrics", s.handleMetrics)

		// sing-box config
		api.GET("/singbox/preview", s.handleSingboxPreview)
	}

	// Start SSE background push loops
	startSSELoops(s)

	return r
}

// NewTestRouter builds a router with injected dependencies for testing.
// Does NOT start SSE loops to avoid goroutine leaks in tests.
func NewTestRouter(cfg *config.Config, store *state.Store, monitor *health.Monitor, rt RuntimeService, auditLog *audit.Logger) http.Handler {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())

	authMgr := auth.NewManager(cfg.DataDir)

	s := &Server{
		cfg:     cfg,
		store:   store,
		monitor: monitor,
		auth:    authMgr,
		rt:      rt,
		audit:   auditLog,
	}

	r.Use(s.corsMiddleware())
	r.Use(s.securityHeadersMiddleware())
	r.Use(s.authMiddleware())

	r.GET("/", s.handleIndex)
	r.GET("/captive", s.handleCaptive)

	api := r.Group("/api")
	{
		api.GET("/auth/status", s.handleAuthStatus)
		api.POST("/auth/login", s.handleAuthLogin)
		api.POST("/auth/logout", s.handleAuthLogout)
		api.POST("/auth/setup", s.handleAuthSetup)
		api.POST("/auth/disable", s.handleAuthDisable)
		api.POST("/auth/readonly", s.handleAuthReadonly)

		api.GET("/status", s.handleStatus)
		api.GET("/health", s.handleHealth)
		api.GET("/alerts", s.handleAlerts)
		api.POST("/alerts/:id/ack", s.handleAlertAck)
		api.GET("/captive/status", s.handleCaptiveStatus)

		api.GET("/egress/node/:tag", s.handleEgressNode)
		api.GET("/egress/device/:mac", s.handleEgressDevice)
		api.GET("/egress/router", s.handleEgressRouter)

		api.GET("/settings", s.handleSettings)
		api.PUT("/settings", s.readonlyGuard(), s.handleSettingsUpdate)
		api.POST("/service/toggle", s.readonlyGuard(), s.handleToggle)

		api.GET("/sources", s.handleSources)
		api.POST("/sources", s.readonlyGuard(), s.handleSourceCreate)
		api.PUT("/sources/:sid", s.readonlyGuard(), s.handleSourceUpdate)
		api.DELETE("/sources/:sid", s.readonlyGuard(), s.handleSourceDelete)
		api.POST("/sources/:sid/sync", s.readonlyGuard(), s.handleSourceSync)

		api.GET("/nodes", s.handleNodes)
		api.POST("/nodes/manual", s.readonlyGuard(), s.handleNodeManual)
		api.POST("/nodes/import-link/preview", s.handleNodeImportPreview)
		api.POST("/nodes/import-link", s.readonlyGuard(), s.handleNodeImportLink)
		api.POST("/nodes/sync-all", s.readonlyGuard(), s.handleSyncAll)
		api.PUT("/nodes/:tag", s.readonlyGuard(), s.handleNodeUpdate)
		api.DELETE("/nodes/:tag", s.readonlyGuard(), s.handleNodeDelete)
		api.POST("/nodes/batch", s.readonlyGuard(), s.handleNodeBatch)
		api.PUT("/nodes/:tag/toggle", s.readonlyGuard(), s.handleNodeToggle)
		api.POST("/nodes/:tag/test", s.handleNodeTest)
		api.POST("/nodes/:tag/speedtest", s.handleNodeSpeedtest)
		api.POST("/nodes/health/refresh", s.readonlyGuard(), s.handleNodesHealthRefresh)

		api.GET("/subscriptions", s.handleSubscriptions)
		api.POST("/subscriptions", s.readonlyGuard(), s.handleSubCreate)
		api.PUT("/subscriptions/:sid", s.readonlyGuard(), s.handleSubUpdate)
		api.DELETE("/subscriptions/:sid", s.readonlyGuard(), s.handleSubDelete)
		api.POST("/subscriptions/:sid/sync", s.readonlyGuard(), s.handleSubSync)

		api.GET("/devices", s.handleDevices)
		api.POST("/devices", s.readonlyGuard(), s.handleDeviceUpsert)
		api.POST("/devices/batch", s.readonlyGuard(), s.handleDeviceBatch)
		api.PUT("/devices/:mac/node", s.readonlyGuard(), s.handleDeviceSetNode)
		api.PUT("/devices/:mac/remark", s.readonlyGuard(), s.handleDeviceRemark)
		api.PUT("/devices/:mac/ip", s.readonlyGuard(), s.handleDeviceIP)
		api.DELETE("/devices/:mac", s.readonlyGuard(), s.handleDeviceDelete)

		api.GET("/system/info", s.handleSystemInfo)
		api.GET("/update/check", s.handleUpdateCheck)
		api.POST("/update/apply", s.readonlyGuard(), s.handleUpdateApply)

		api.GET("/traffic/realtime", s.handleTrafficRealtime)
		api.GET("/traffic/connections", s.handleTrafficConnections)

		api.GET("/events", s.handleSSE)
		api.GET("/logs", s.handleLogs)
		api.GET("/logs/tail", s.handleLogsTail)
		api.POST("/logs/clear", s.readonlyGuard(), s.handleLogsClear)
		api.GET("/dhcp/discover", s.handleDHCPDiscover)
		api.GET("/dhcp/leases", s.handleDHCPLeases)
		api.POST("/dhcp/bind", s.readonlyGuard(), s.handleDHCPBind)
		api.DELETE("/dhcp/bind/:mac", s.readonlyGuard(), s.handleDHCPBindDelete)
		api.POST("/apply", s.readonlyGuard(), s.handleApply)
		api.POST("/rollback", s.readonlyGuard(), s.handleRollback)

		api.GET("/metrics", s.handleMetrics)

		api.GET("/singbox/preview", s.handleSingboxPreview)
	}

	return r
}

// ── Middleware ──

// isPrivateLANOrigin returns true for any http/https origin whose host
// resolves to a private RFC-1918 address or loopback.  This lets the web
// panel work regardless of the router's LAN subnet (192.168.x.x, 10.x.x.x,
// 172.16-31.x.x, or 127.x).
func isPrivateLANOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	// Strip scheme (http:// or https://)
	host := origin
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	// Strip path / query
	if idx := strings.IndexByte(host, '/'); idx >= 0 {
		host = host[:idx]
	}
	// Strip port — handle IPv6 [::1]:port
	if len(host) > 0 && host[0] == '[' {
		if end := strings.IndexByte(host, ']'); end >= 0 {
			host = host[1:end]
		}
	} else if idx := strings.LastIndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
		(ip4[0] == 192 && ip4[1] == 168)
}

func (s *Server) corsMiddleware() gin.HandlerFunc {
	origins := make(map[string]bool, len(s.cfg.CORSOrigins))
	for _, o := range s.cfg.CORSOrigins {
		origins[o] = true
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origins[origin] || isPrivateLANOrigin(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, Authorization")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func (s *Server) securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if auth.IsPathPublic(path) {
			c.Next()
			return
		}
		cfg := s.auth.LoadAuth()
		if !cfg.AuthEnabled {
			c.Set("role", "admin")
			c.Next()
			return
		}
		// Allow setup when no password set
		if path == "/api/auth/setup" && cfg.PasswordHash == "" {
			c.Next()
			return
		}
		// Check token from header, cookie, or bearer
		token := c.GetHeader("X-Auth-Token")
		if token == "" {
			token, _ = c.Cookie("macflow_token")
		}
		if token == "" {
			if h := c.GetHeader("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
				token = h[7:]
			}
		}
		if s.auth.ValidateSession(token) {
			role := s.auth.GetSessionRole(token)
			if role == "" {
				role = "admin"
			}
			c.Set("role", role)
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"detail":        "认证失败，请重新登录",
			"auth_required": true,
		})
	}
}

// readonlyGuard blocks write operations for readonly sessions.
func (s *Server) readonlyGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		if role == "readonly" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"detail": "只读模式，无权执行此操作",
			})
			return
		}
		c.Next()
	}
}

// ── bootTime for uptime calculation ──

var bootTime = time.Now()
