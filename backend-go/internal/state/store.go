// Package state manages the persistent JSON state (state.json) with
// thread-safe access via sync.RWMutex. It replaces Python's read_state/write_state
// pattern with a single, in-memory state protected by a lock.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State represents the full application state persisted to state.json.
type State struct {
	Enabled         bool            `json:"enabled"`
	DefaultPolicy   string          `json:"default_policy"`
	FailurePolicy   string          `json:"failure_policy"`
	DNS             DNSConfig       `json:"dns"`
	XUISourceList   []XUISource     `json:"xui_sources"`
	Subscriptions   []Subscription  `json:"subscriptions"`
	Nodes           []Node          `json:"nodes"`
	Devices         []Device        `json:"devices"`
	LastSync        int64           `json:"last_sync"`
	LastApply       int64           `json:"last_apply"`
	PolicyVersion   *string         `json:"policy_version"`
	RollbackVersion *string         `json:"rollback_version"`
}

// DNSConfig holds DNS-related settings.
type DNSConfig struct {
	EnforceRedirectPort int      `json:"enforce_redirect_port"`
	BlockDOHDOQ         bool     `json:"block_doh_doq"`
	Servers             []string `json:"servers"`
	ForceRedirect       bool     `json:"force_redirect"`
}

// XUISource represents a 3x-UI panel source.
type XUISource struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	BaseURL   string `json:"base_url"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Enabled   bool   `json:"enabled"`
	LastSync  int64  `json:"last_sync"`
	LastError string `json:"last_error,omitempty"`
}

// Subscription represents a node subscription.
type Subscription struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers,omitempty"`
	LastSync int64             `json:"last_sync"`
}

// Node represents a proxy node.
type Node struct {
	Tag          string                 `json:"tag"`
	Type         string                 `json:"type"`
	Server       string                 `json:"server"`
	ServerPort   int                    `json:"server_port"`
	Password     string                 `json:"password,omitempty"`
	UUID         string                 `json:"uuid,omitempty"`
	Method       string                 `json:"method,omitempty"`
	Flow         string                 `json:"flow,omitempty"`
	Security     string                 `json:"security,omitempty"`
	Username     string                 `json:"username,omitempty"`
	Transport    map[string]interface{} `json:"transport,omitempty"`
	TLS          map[string]interface{} `json:"tls,omitempty"`
	Source       string                 `json:"source,omitempty"`
	SourceType   string                 `json:"source_type,omitempty"`
	Enabled      bool                   `json:"enabled"`
	Latency      *int                   `json:"latency"`
	SpeedMbps    float64                `json:"speed_mbps"`
	HealthScore  int                    `json:"health_score"`
	HealthStatus string                 `json:"health_status"`
	HealthFails  int                    `json:"health_failures"`
	LastProbeAt  int64                  `json:"last_probe_at"`
	LastProbeOK  int64                  `json:"last_probe_ok_at"`
	LastProbeErr string                 `json:"last_probe_error"`
}

// Device represents a managed network device.
type Device struct {
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	NodeTag string `json:"node_tag"`
	Managed bool   `json:"managed"`
	Remark  string `json:"remark"`
	IP      string `json:"ip"`
	LastIP  string `json:"last_ip"`
	Mark    int    `json:"mark"`
}

// Store is a thread-safe state manager that persists to disk.
type Store struct {
	mu       sync.RWMutex
	state    State
	filePath string
	mtime    time.Time
}

// InitialState returns the default state.
func InitialState() State {
	return State{
		Enabled:       false,
		DefaultPolicy: "whitelist",
		FailurePolicy: "fail-close",
		DNS: DNSConfig{
			EnforceRedirectPort: 6053,
			BlockDOHDOQ:         true,
			Servers:             []string{"8.8.8.8", "1.1.1.1"},
			ForceRedirect:       true,
		},
		XUISourceList: []XUISource{},
		Subscriptions: []Subscription{},
		Nodes:         []Node{},
		Devices:       []Device{},
	}
}

// NewStore creates a new Store, loading state from disk or initializing defaults.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	s := &Store{
		filePath: filepath.Join(dataDir, "state.json"),
	}

	if err := s.load(); err != nil {
		// Corrupt or missing — initialize with defaults
		s.state = InitialState()
		if err := s.persist(); err != nil {
			return nil, fmt.Errorf("write initial state: %w", err)
		}
	}

	return s, nil
}

// Read returns a deep copy of the current state (safe for concurrent use).
func (s *Store) Read() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deepCopy()
}

// Update atomically modifies the state using a callback.
// The callback receives a pointer to the state; changes are persisted after return.
func (s *Store) Update(fn func(st *State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.state)
	return s.persist()
}

// load reads state from disk.
func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("empty state file")
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse state: %w", err)
	}
	s.state = st
	if info, err := os.Stat(s.filePath); err == nil {
		s.mtime = info.ModTime()
	}
	return nil
}

// persist writes the current state atomically to disk.
func (s *Store) persist() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.filePath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if info, err := os.Stat(s.filePath); err == nil {
		s.mtime = info.ModTime()
	}
	return nil
}

// deepCopy returns a JSON round-trip copy of the state.
func (s *Store) deepCopy() State {
	data, _ := json.Marshal(s.state)
	var copy State
	json.Unmarshal(data, &copy)
	return copy
}

// NextMark allocates the next unused fwmark for a device.
func (s *Store) NextMark() int {
	maxMark := 0x100
	for _, d := range s.state.Devices {
		if d.Mark >= maxMark {
			maxMark = d.Mark + 1
		}
	}
	return maxMark
}
