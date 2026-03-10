// Package audit provides structured audit logging.
package audit

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Logger writes audit events to a JSON-lines file.
type Logger struct {
	mu       sync.Mutex
	filePath string
}

// NewLogger creates an audit logger writing to dataDir/audit.jsonl.
func NewLogger(dataDir string) *Logger {
	return &Logger{
		filePath: filepath.Join(dataDir, "audit.jsonl"),
	}
}

// Entry represents a single audit log entry.
type Entry struct {
	Timestamp string `json:"ts"`
	Action    string `json:"action"`
	Detail    string `json:"detail,omitempty"`
}

// Log records an audit event.
func (l *Logger) Log(action, detail string) {
	entry := Entry{
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    action,
		Detail:    detail,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[audit] marshal error: %v", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("[audit] open error: %v", err)
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "%s\n", data)
}
