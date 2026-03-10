package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"macflow/internal/singbox"
)

// handleTrafficRealtime returns realtime traffic from Clash API.
//
// GET /api/traffic/realtime
func (s *Server) handleTrafficRealtime(c *gin.Context) {
	data, err := singbox.GetTraffic()
	ts := time.Now().Unix()

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"up_bytes":  0,
			"down_bytes": 0,
			"up_str":    "0 B/s",
			"down_str":  "0 B/s",
			"ts":        ts,
		})
		return
	}

	up, _ := data["up"].(float64)
	down, _ := data["down"].(float64)

	c.JSON(http.StatusOK, gin.H{
		"up_bytes":  int64(up),
		"down_bytes": int64(down),
		"up_str":    fmtBytes(int64(up)) + "/s",
		"down_str":  fmtBytes(int64(down)) + "/s",
		"ts":        ts,
	})
}

// handleTrafficConnections returns active connections from Clash API.
//
// GET /api/traffic/connections
func (s *Server) handleTrafficConnections(c *gin.Context) {
	data, err := singbox.GetConnections()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"count":           0,
			"upload_total":    0,
			"download_total":  0,
			"upload_total_str": "0 B",
			"download_total_str": "0 B",
		})
		return
	}

	connections, _ := data["connections"].([]interface{})
	count := len(connections)
	uploadTotal, _ := data["uploadTotal"].(float64)
	downloadTotal, _ := data["downloadTotal"].(float64)

	c.JSON(http.StatusOK, gin.H{
		"count":             count,
		"upload_total":      int64(uploadTotal),
		"download_total":    int64(downloadTotal),
		"upload_total_str":  fmtBytes(int64(uploadTotal)),
		"download_total_str": fmtBytes(int64(downloadTotal)),
	})
}

// fmtBytes formats bytes to human-readable string.
func fmtBytes(n int64) string {
	if n < 0 {
		n = 0
	}
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
