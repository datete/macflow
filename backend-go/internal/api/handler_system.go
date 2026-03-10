package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	githubRepo = "datete/macflow"
	githubRaw  = "https://raw.githubusercontent.com/" + githubRepo + "/main/"
	githubAPI  = "https://api.github.com/repos/" + githubRepo
)

// handleSystemInfo returns system runtime info.
//
// GET /api/system/info
func (s *Server) handleSystemInfo(c *gin.Context) {
	uptimeSec := int(time.Since(bootTime).Seconds())
	h := uptimeSec / 3600
	m := (uptimeSec % 3600) / 60
	sec := uptimeSec % 60
	uptimeStr := fmt.Sprintf("%dh %dm %ds", h, m, sec)

	// Memory usage from runtime
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	memMB := float64(mem.Alloc) / (1024 * 1024)

	probeCycle := s.monitor.GetProbeCycle()

	c.JSON(http.StatusOK, gin.H{
		"uptime_sec":  uptimeSec,
		"uptime_str":  uptimeStr,
		"memory_mb":   fmt.Sprintf("%.1f", memMB),
		"pid":         os.Getpid(),
		"probe_cycle": probeCycle,
		"boot_time":   bootTime.Unix(),
		"go_version":  runtime.Version(),
		"version":     s.cfg.Version,
	})
}

// handleUpdateCheck checks GitHub for updates.
//
// GET /api/update/check
func (s *Server) handleUpdateCheck(c *gin.Context) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Get remote commit
	req, _ := http.NewRequest("GET", githubAPI+"/commits/main", nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"available": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.JSON(http.StatusOK, gin.H{"available": false, "error": fmt.Sprintf("GitHub API returned %d", resp.StatusCode)})
		return
	}

	// Parse response — simplified, extract sha
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	// Quick JSON field extraction without full unmarshal
	remoteSHA := extractJSONField(string(body), "sha")
	if len(remoteSHA) > 8 {
		remoteSHA = remoteSHA[:8]
	}
	remoteMessage := extractJSONField(string(body), "message")
	remoteDate := extractJSONField(string(body), "date")

	// Get local commit
	localSHA := ""
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	if out, err := cmd.Output(); err == nil {
		localSHA = strings.TrimSpace(string(out))
	}

	available := remoteSHA != localSHA && remoteSHA != ""

	c.JSON(http.StatusOK, gin.H{
		"available":      available,
		"local_version":  localSHA,
		"remote_version": remoteSHA,
		"remote_message": remoteMessage,
		"remote_date":    remoteDate,
	})
}

// handleUpdateApply pulls updated files from GitHub.
//
// POST /api/update/apply
func (s *Server) handleUpdateApply(c *gin.Context) {
	updateFiles := []string{
		"backend/main.py", "web/index.html", "web/captive.html",
		"core/apply/atomic_apply.sh", "core/apply/device_patch.sh",
		"core/dns/dns_leak_probe.sh", "core/rule-engine/render_policy.py",
	}

	rootDir := filepath.Dir(filepath.Dir(s.cfg.DataDir))
	client := &http.Client{Timeout: 15 * time.Second}

	// Fetch checksums
	checksums := map[string]string{}
	if resp, err := client.Get(githubRaw + "checksums.sha256"); err == nil {
		defer resp.Body.Close()
		if body, err := io.ReadAll(io.LimitReader(resp.Body, 65536)); err == nil {
			for _, line := range strings.Split(string(body), "\n") {
				parts := strings.Fields(line)
				if len(parts) == 2 {
					checksums[parts[1]] = parts[0]
				}
			}
		}
	}

	var updated, errors, integrityFailures []string
	restartScheduled := false

	for _, fpath := range updateFiles {
		// Path traversal protection
		target := filepath.Join(rootDir, fpath)
		absTarget, _ := filepath.Abs(target)
		absRoot, _ := filepath.Abs(rootDir)
		if !strings.HasPrefix(absTarget, absRoot) {
			errors = append(errors, fmt.Sprintf("%s: path traversal blocked", fpath))
			continue
		}

		// Download
		resp, err := client.Get(githubRaw + fpath)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: download failed: %v", fpath, err))
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		resp.Body.Close()
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: read failed: %v", fpath, err))
			continue
		}
		if resp.StatusCode != 200 {
			errors = append(errors, fmt.Sprintf("%s: HTTP %d", fpath, resp.StatusCode))
			continue
		}

		// SHA-256 integrity check
		if expected, ok := checksums[fpath]; ok {
			h := sha256.Sum256(body)
			actual := hex.EncodeToString(h[:])
			if actual != expected {
				integrityFailures = append(integrityFailures, fpath)
				continue
			}
		}

		// Ensure directory exists and write
		os.MkdirAll(filepath.Dir(target), 0755)
		if err := os.WriteFile(target, body, 0644); err != nil {
			errors = append(errors, fmt.Sprintf("%s: write failed: %v", fpath, err))
			continue
		}
		updated = append(updated, fpath)
	}

	// Schedule restart if backend was updated
	for _, f := range updated {
		if strings.Contains(f, "main.py") || strings.Contains(f, "main.go") {
			restartScheduled = true
			go func() {
				time.Sleep(2 * time.Second)
				exec.Command("sh", "-c", "service macflow restart 2>/dev/null || kill -HUP 1").Run()
			}()
			break
		}
	}

	s.audit.Log("cloud_update", fmt.Sprintf("updated=%v errors=%v", updated, errors))

	c.JSON(http.StatusOK, gin.H{
		"ok":                  len(errors) == 0 && len(integrityFailures) == 0,
		"updated":             updated,
		"errors":              errors,
		"integrity_failures":  integrityFailures,
		"restart_scheduled":   restartScheduled,
	})
}

// extractJSONField does a quick-and-dirty extraction of a string field from JSON.
func extractJSONField(jsonStr, field string) string {
	key := fmt.Sprintf(`"%s"`, field)
	idx := strings.Index(jsonStr, key)
	if idx < 0 {
		return ""
	}
	rest := jsonStr[idx+len(key):]
	rest = strings.TrimLeft(rest, ": \t\n\r")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}
