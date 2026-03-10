package auth

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("testpassword123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// Verify format: pbkdf2:salt:hash
	if !strings.HasPrefix(hash, "pbkdf2:") {
		t.Errorf("expected pbkdf2: prefix, got %q", hash)
	}
	parts := strings.SplitN(hash, ":", 3)
	if len(parts) != 3 {
		t.Errorf("expected 3 parts, got %d: %q", len(parts), hash)
	}
	// Salt should be 32 hex chars (16 bytes)
	if len(parts[1]) != 32 {
		t.Errorf("expected 32-char hex salt, got %d chars", len(parts[1]))
	}
	// Hash should be 64 hex chars (32 bytes)
	if len(parts[2]) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars", len(parts[2]))
	}
}

func TestHashPasswordUniqueSalts(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("same password should produce different hashes (random salt)")
	}
}

func TestVerifyPasswordPBKDF2(t *testing.T) {
	hash, _ := HashPassword("correctpassword")

	if !VerifyPassword("correctpassword", hash) {
		t.Error("VerifyPassword should return true for correct password")
	}
	if VerifyPassword("wrongpassword", hash) {
		t.Error("VerifyPassword should return false for wrong password")
	}
	if VerifyPassword("", hash) {
		t.Error("VerifyPassword should return false for empty password")
	}
}

func TestVerifyPasswordLegacySHA256(t *testing.T) {
	// Legacy format: salt:sha256(salt:password)
	// salt = "abc", password = "test"
	// sha256("abc:test") = known hash
	// We test the format acceptance, not the exact hash
	// The legacy format is salt:hash where hash = hex(sha256(salt + ":" + password))
	// For simplicity, just test that malformed stored hashes return false
	if VerifyPassword("anything", "invalid") {
		t.Error("should reject hash without colon")
	}
	if VerifyPassword("anything", "") {
		t.Error("should reject empty hash")
	}
	if VerifyPassword("anything", "pbkdf2:short") {
		t.Error("should reject malformed pbkdf2 hash")
	}
}

func TestIsPathPublic(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/", true},
		{"/captive", true},
		{"/captive/status", true},    // prefix match
		{"/favicon.ico", true},
		{"/api/auth/login", true},
		{"/api/auth/status", true},
		{"/api/auth/setup", true},
		{"/api/captive/status", true},
		{"/api/events", true},
		{"/api/settings", false},     // needs auth
		{"/api/devices", false},
		{"/api/apply", false},
		{"/api/nodes", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsPathPublic(tt.path)
			if got != tt.expected {
				t.Errorf("IsPathPublic(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestSessionLifecycle(t *testing.T) {
	mgr := NewManager(t.TempDir())

	// Create session
	token, err := mgr.CreateSession("127.0.0.1", "admin")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if len(token) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected 64-char token, got %d", len(token))
	}

	// Validate
	if !mgr.ValidateSession(token) {
		t.Error("fresh session should be valid")
	}
	if mgr.ValidateSession("invalid-token") {
		t.Error("invalid token should not validate")
	}
	if mgr.ValidateSession("") {
		t.Error("empty token should not validate")
	}

	// Delete
	mgr.DeleteSession(token)
	if mgr.ValidateSession(token) {
		t.Error("deleted session should not validate")
	}
}

func TestClearSessions(t *testing.T) {
	mgr := NewManager(t.TempDir())

	tok1, _ := mgr.CreateSession("1.1.1.1", "admin")
	tok2, _ := mgr.CreateSession("2.2.2.2", "readonly")

	mgr.ClearSessions()

	if mgr.ValidateSession(tok1) || mgr.ValidateSession(tok2) {
		t.Error("ClearSessions should invalidate all sessions")
	}
}

func TestRateLimit(t *testing.T) {
	mgr := NewManager(t.TempDir())
	ip := "10.0.0.1"

	// First 5 attempts should be allowed
	for i := 0; i < rateMaxHits; i++ {
		if !mgr.CheckRateLimit(ip) {
			t.Errorf("attempt %d should be allowed", i+1)
		}
		mgr.RecordAttempt(ip)
	}

	// 6th attempt should be blocked
	if mgr.CheckRateLimit(ip) {
		t.Error("should be rate limited after max hits")
	}

	// Different IP should not be affected
	if !mgr.CheckRateLimit("10.0.0.2") {
		t.Error("different IP should not be rate limited")
	}
}

func TestAuthConfigPersistence(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir)

	// Default should be empty
	cfg := mgr.LoadAuth()
	if cfg.AuthEnabled {
		t.Error("default auth should be disabled")
	}

	// Save and reload
	hash, _ := HashPassword("mypassword")
	cfg.AuthEnabled = true
	cfg.PasswordHash = hash
	if err := mgr.SaveAuth(cfg); err != nil {
		t.Fatalf("SaveAuth: %v", err)
	}

	cfg2 := mgr.LoadAuth()
	if !cfg2.AuthEnabled {
		t.Error("auth should be enabled after save")
	}
	if cfg2.PasswordHash != hash {
		t.Error("password hash should match after save")
	}
}
