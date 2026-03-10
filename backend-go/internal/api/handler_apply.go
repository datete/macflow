package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/singbox"
	"macflow/internal/state"
)

// handleApply triggers a full runtime reconciliation:
// 1. Generate a policy_version
// 2. Save current version as rollback_version
// 3. Run HotApply (nftables + sing-box + ip rules)
// 4. Return results
//
// POST /api/apply
func (s *Server) handleApply(c *gin.Context) {
	st := s.store.Read()
	if !st.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "服务未启用"})
		return
	}

	// Count enabled nodes
	enabledCount := 0
	for _, n := range st.Nodes {
		if n.Enabled {
			enabledCount++
		}
	}
	if enabledCount == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "没有可用的已启用节点"})
		return
	}

	// Generate version string
	version := fmt.Sprintf("v%d", time.Now().UnixMilli())

	// Save rollback and set new version
	s.store.Update(func(st *state.State) {
		if st.PolicyVersion != nil {
			st.RollbackVersion = st.PolicyVersion
		}
		st.PolicyVersion = &version
		st.LastApply = time.Now().Unix()
	})

	// Execute hot-apply
	result := s.rt.HotApply(true)

	s.audit.Log("apply", fmt.Sprintf("version=%s singbox=%s nft=%s iprules=%s",
		version, result.Singbox, result.Nftables, result.IPRules))

	c.JSON(http.StatusOK, gin.H{
		"status":         "applied",
		"policy_version": version,
		"singbox":        result.Singbox,
		"nftables":       result.Nftables,
		"ip_rules":       result.IPRules,
	})
}

// handleRollback reverts to the previous policy version:
// 1. Check rollback_version exists
// 2. Swap policy_version ↔ rollback_version
// 3. Run HotApply to re-apply the previous state
//
// POST /api/rollback
func (s *Server) handleRollback(c *gin.Context) {
	st := s.store.Read()
	if st.RollbackVersion == nil || *st.RollbackVersion == "" {
		c.JSON(http.StatusBadRequest, gin.H{"detail": "没有可回滚的版本"})
		return
	}

	rollbackVer := *st.RollbackVersion

	// Swap versions
	s.store.Update(func(st *state.State) {
		st.PolicyVersion, st.RollbackVersion = st.RollbackVersion, st.PolicyVersion
		st.LastApply = time.Now().Unix()
	})

	// Re-apply
	result := s.rt.HotApply(true)

	s.audit.Log("rollback", fmt.Sprintf("to_version=%s singbox=%s nft=%s iprules=%s",
		rollbackVer, result.Singbox, result.Nftables, result.IPRules))

	c.JSON(http.StatusOK, gin.H{
		"status":           "rolled_back",
		"policy_version":   rollbackVer,
		"singbox":          result.Singbox,
		"nftables":         result.Nftables,
		"ip_rules":         result.IPRules,
	})
}

// handleSingboxPreview returns the generated sing-box config JSON
// without actually applying it. Useful for debugging.
//
// GET /api/singbox/preview
func (s *Server) handleSingboxPreview(c *gin.Context) {
	st := s.store.Read()
	cfg, err := singbox.BuildConfig(st)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cfg)
}
