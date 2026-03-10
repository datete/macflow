package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

const logFileName = "macflow.log"

// handleLogs returns log entries with optional filtering.
//
// GET /api/logs?lines=100&level=&component=&event=&q=
func (s *Server) handleLogs(c *gin.Context) {
	lines := 100
	if l := c.Query("lines"); l != "" {
		if v, err := parseInt(l); err == nil && v >= 1 {
			lines = v
		}
	}
	if lines > 5000 {
		lines = 5000
	}

	level := c.Query("level")
	component := c.Query("component")
	event := c.Query("event")
	q := strings.ToLower(c.Query("q")) // free-text search (case-insensitive)
	hasFilter := level != "" || component != "" || event != "" || q != ""

	logPath := filepath.Join(s.cfg.DataDir, logFileName)

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}

	if !hasFilter {
		// Efficient tail read
		entries := tailLogFile(logPath, lines)
		c.JSON(http.StatusOK, entries)
		return
	}

	// Full read with filtering
	f, err := os.Open(logPath)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer f.Close()

	var allEntries []map[string]interface{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var entry map[string]interface{}
		if json.Unmarshal([]byte(line), &entry) != nil {
			// Non-JSON line
			entry = map[string]interface{}{
				"ts":        "",
				"level":     "info",
				"component": "system",
				"event":     "legacy",
				"message":   line,
			}
		}

		// Apply filters
		if level != "" {
			if v, ok := entry["level"].(string); !ok || v != level {
				continue
			}
		}
		if component != "" {
			if v, ok := entry["component"].(string); !ok || v != component {
				continue
			}
		}
		if event != "" {
			if v, ok := entry["event"].(string); !ok || v != event {
				continue
			}
		}
		if q != "" {
			// Free-text search across message, event, component fields
			haystack := strings.ToLower(
				fmt.Sprintf("%v %v %v %v",
					entry["message"], entry["event"], entry["component"], entry["details"]),
			)
			if !strings.Contains(haystack, q) {
				continue
			}
		}

		allEntries = append(allEntries, entry)
	}

	// Take last N
	if len(allEntries) > lines {
		allEntries = allEntries[len(allEntries)-lines:]
	}
	if allEntries == nil {
		allEntries = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, allEntries)
}

// handleLogsClear clears the log file.
//
// POST /api/logs/clear
func (s *Server) handleLogsClear(c *gin.Context) {
	logPath := filepath.Join(s.cfg.DataDir, logFileName)
	if _, err := os.Stat(logPath); err == nil {
		os.WriteFile(logPath, []byte(""), 0644)
	}
	s.audit.Log("logs_clear", "all logs cleared")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// tailLogFile reads the last N lines from a file efficiently.
func tailLogFile(path string, n int) []map[string]interface{} {
	f, err := os.Open(path)
	if err != nil {
		return []map[string]interface{}{}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return []map[string]interface{}{}
	}

	// Estimate chunk size
	chunkSize := int64(n)*250 + 4096
	if chunkSize > info.Size() {
		chunkSize = info.Size()
	}

	offset := info.Size() - chunkSize
	if offset < 0 {
		offset = 0
	}

	f.Seek(offset, 0)
	buf := make([]byte, chunkSize)
	nRead, _ := f.Read(buf)
	buf = buf[:nRead]

	// Split into lines
	allLines := strings.Split(string(buf), "\n")

	// If we didn't read from start, first line might be partial — skip it
	if offset > 0 && len(allLines) > 0 {
		allLines = allLines[1:]
	}

	// Take last N non-empty lines
	var validLines []string
	for _, line := range allLines {
		if strings.TrimSpace(line) != "" {
			validLines = append(validLines, line)
		}
	}
	if len(validLines) > n {
		validLines = validLines[len(validLines)-n:]
	}

	// Parse
	var entries []map[string]interface{}
	for _, line := range validLines {
		var entry map[string]interface{}
		if json.Unmarshal([]byte(line), &entry) != nil {
			entry = map[string]interface{}{
				"ts":        "",
				"level":     "info",
				"component": "system",
				"event":     "legacy",
				"message":   line,
			}
		}
		entries = append(entries, entry)
	}

	if entries == nil {
		entries = []map[string]interface{}{}
	}
	return entries
}
