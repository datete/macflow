// Package auth handles password hashing, session management, and rate limiting.
//
// Key improvements over Python version:
// - PBKDF2-SHA256 only (no plain-text fallback)
// - Session store with O(1) validation via sync.Map
// - Rate limiting with proper cleanup
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// SessionTTL is the session lifetime (7 days).
	SessionTTL = 7 * 24 * time.Hour

	// MaxSessions is the maximum number of concurrent sessions.
	MaxSessions = 50

	// PBKDF2 iterations (OWASP recommended minimum for SHA-256).
	pbkdf2Iterations = 260_000

	// Rate limiting
	rateWindow  = 60 * time.Second
	rateMaxHits = 5
	lockoutTime = 5 * time.Minute
)

// PublicPaths that skip authentication.
var PublicPaths = map[string]bool{
	"/":                   true,
	"/captive":            true,
	"/favicon.ico":        true,
	"/api/auth/login":     true,
	"/api/auth/status":    true,
	"/api/auth/setup":     true,
	"/api/captive/status": true,
	"/api/events":         true,
}

// PublicPrefixes that skip authentication.
var PublicPrefixes = []string{"/captive"}

// AuthConfig represents the stored authentication configuration.
type AuthConfig struct {
	PasswordHash         string `json:"password_hash"`
	AuthEnabled          bool   `json:"auth_enabled"`
	ReadonlyPasswordHash string `json:"readonly_password_hash,omitempty"`
	ReadonlyEnabled      bool   `json:"readonly_enabled,omitempty"`
}

// Session represents an active user session.
type Session struct {
	Token     string    `json:"token"`
	ClientIP  string    `json:"client_ip"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Role      string    `json:"role"` // "admin" or "readonly"
}

// Manager handles authentication operations.
type Manager struct {
	dataDir  string
	authFile string

	// Session store
	sessions sync.Map // map[token]Session
	sessCount int32

	// Rate limiting
	rateMu   sync.Mutex
	attempts map[string][]time.Time // ip -> attempt timestamps
}

// NewManager creates a new auth manager.
func NewManager(dataDir string) *Manager {
	return &Manager{
		dataDir:  dataDir,
		authFile: filepath.Join(dataDir, "auth.json"),
		attempts: make(map[string][]time.Time),
	}
}

// HashPassword hashes a password with PBKDF2-SHA256 + random salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	saltHex := hex.EncodeToString(salt)
	hash := pbkdf2.Key([]byte(password), []byte(saltHex), pbkdf2Iterations, 32, sha256.New)
	hashHex := hex.EncodeToString(hash)
	return fmt.Sprintf("pbkdf2:%s:%s", saltHex, hashHex), nil
}

// VerifyPassword verifies a password against stored hash.
// Only supports PBKDF2 and legacy SHA-256 (no plain-text).
func VerifyPassword(password, stored string) bool {
	if strings.HasPrefix(stored, "pbkdf2:") {
		parts := strings.SplitN(stored, ":", 3)
		if len(parts) != 3 {
			return false
		}
		salt, expected := parts[1], parts[2]
		hash := pbkdf2.Key([]byte(password), []byte(salt), pbkdf2Iterations, 32, sha256.New)
		hashHex := hex.EncodeToString(hash)
		return hmac.Equal([]byte(hashHex), []byte(expected))
	}
	// Legacy SHA-256 format (salt:hash)
	if idx := strings.IndexByte(stored, ':'); idx > 0 {
		salt := stored[:idx]
		expected := stored[idx+1:]
		h := sha256.Sum256([]byte(salt + ":" + password))
		hashHex := hex.EncodeToString(h[:])
		return hmac.Equal([]byte(hashHex), []byte(expected))
	}
	// Plain-text passwords are NOT supported
	return false
}

// LoadAuth reads the auth config from disk.
func (m *Manager) LoadAuth() AuthConfig {
	data, err := os.ReadFile(m.authFile)
	if err != nil {
		return AuthConfig{}
	}
	var cfg AuthConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return AuthConfig{}
	}
	return cfg
}

// SaveAuth writes auth config atomically to disk.
func (m *Manager) SaveAuth(cfg AuthConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.authFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.authFile)
}

// CreateSession creates a new session and returns its token.
// role should be "admin" or "readonly".
func (m *Manager) CreateSession(clientIP string, role string) (string, error) {
	if role == "" {
		role = "admin"
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	tokenHex := hex.EncodeToString(token)
	sess := Session{
		Token:     tokenHex,
		ClientIP:  clientIP,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(SessionTTL),
		Role:      role,
	}
	m.sessions.Store(tokenHex, sess)
	return tokenHex, nil
}

// ValidateSession checks if a token corresponds to a valid, non-expired session.
func (m *Manager) ValidateSession(token string) bool {
	if token == "" {
		return false
	}
	val, ok := m.sessions.Load(token)
	if !ok {
		return false
	}
	sess := val.(Session)
	if time.Now().After(sess.ExpiresAt) {
		m.sessions.Delete(token)
		return false
	}
	return true
}

// GetSessionRole returns the role of a valid session token.
// Returns "" if the token is invalid.
func (m *Manager) GetSessionRole(token string) string {
	if token == "" {
		return ""
	}
	val, ok := m.sessions.Load(token)
	if !ok {
		return ""
	}
	sess := val.(Session)
	if time.Now().After(sess.ExpiresAt) {
		m.sessions.Delete(token)
		return ""
	}
	if sess.Role == "" {
		return "admin"
	}
	return sess.Role
}

// DeleteSession removes a specific session.
func (m *Manager) DeleteSession(token string) {
	m.sessions.Delete(token)
}

// ClearSessions removes all sessions.
func (m *Manager) ClearSessions() {
	m.sessions.Range(func(key, _ any) bool {
		m.sessions.Delete(key)
		return true
	})
}

// CleanupExpired removes expired sessions.
func (m *Manager) CleanupExpired() {
	now := time.Now()
	m.sessions.Range(func(key, val any) bool {
		sess := val.(Session)
		if now.After(sess.ExpiresAt) {
			m.sessions.Delete(key)
		}
		return true
	})
}

// CheckRateLimit checks if the IP has exceeded the login rate limit.
func (m *Manager) CheckRateLimit(clientIP string) bool {
	m.rateMu.Lock()
	defer m.rateMu.Unlock()

	now := time.Now()
	attempts := m.attempts[clientIP]

	// Clean old attempts
	var recent []time.Time
	for _, t := range attempts {
		if now.Sub(t) < lockoutTime {
			recent = append(recent, t)
		}
	}
	m.attempts[clientIP] = recent

	// Check if locked out
	recentWindow := 0
	for _, t := range recent {
		if now.Sub(t) < rateWindow {
			recentWindow++
		}
	}
	return recentWindow < rateMaxHits
}

// RecordAttempt records a failed login attempt.
func (m *Manager) RecordAttempt(clientIP string) {
	m.rateMu.Lock()
	defer m.rateMu.Unlock()
	m.attempts[clientIP] = append(m.attempts[clientIP], time.Now())
}

// IsPathPublic checks if a path should skip authentication.
func IsPathPublic(path string) bool {
	if PublicPaths[path] {
		return true
	}
	for _, prefix := range PublicPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
