package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Clear all config env vars
	for _, key := range []string{
		"MACFLOW_DATA_DIR", "MACFLOW_WEB_DIR", "MACFLOW_LISTEN_PORT",
		"MACFLOW_BIND", "MACFLOW_CLASH_API", "MACFLOW_MIXED_PROXY",
		"MACFLOW_CORS_ORIGINS", "MACFLOW_GITHUB_REPO",
	} {
		os.Unsetenv(key)
	}

	cfg := Load()

	if cfg.ListenPort != 18080 {
		t.Errorf("expected default port 18080, got %d", cfg.ListenPort)
	}
	if cfg.BindAddr != "0.0.0.0" {
		t.Errorf("expected default bind 0.0.0.0, got %q", cfg.BindAddr)
	}
	if cfg.ClashAPI != "http://127.0.0.1:9090" {
		t.Errorf("expected default clash API, got %q", cfg.ClashAPI)
	}
	if len(cfg.CORSOrigins) == 0 {
		t.Error("expected default CORS origins")
	}
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("MACFLOW_LISTEN_PORT", "9999")
	os.Setenv("MACFLOW_BIND", "127.0.0.1")
	os.Setenv("MACFLOW_CORS_ORIGINS", "http://a.com,http://b.com")
	defer func() {
		os.Unsetenv("MACFLOW_LISTEN_PORT")
		os.Unsetenv("MACFLOW_BIND")
		os.Unsetenv("MACFLOW_CORS_ORIGINS")
	}()

	cfg := Load()

	if cfg.ListenPort != 9999 {
		t.Errorf("expected port 9999, got %d", cfg.ListenPort)
	}
	if cfg.BindAddr != "127.0.0.1" {
		t.Errorf("expected bind 127.0.0.1, got %q", cfg.BindAddr)
	}
	if len(cfg.CORSOrigins) != 2 {
		t.Errorf("expected 2 CORS origins, got %d", len(cfg.CORSOrigins))
	}
}

func TestEnvOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envVal   string
		def      string
		expected string
	}{
		{"empty env uses default", "TEST_EMPTY_K", "", "default1", "default1"},
		{"set env uses value", "TEST_SET_K", "custom", "default2", "custom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				os.Setenv(tt.key, tt.envVal)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
			}
			got := envOrDefault(tt.key, tt.def)
			if got != tt.expected {
				t.Errorf("envOrDefault(%q, %q) = %q, want %q", tt.key, tt.def, got, tt.expected)
			}
		})
	}
}

func TestEnvIntOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envVal   string
		def      int
		expected int
	}{
		{"empty uses default", "TEST_INT_E", "", 42, 42},
		{"valid int", "TEST_INT_V", "100", 42, 100},
		{"invalid int uses default", "TEST_INT_I", "abc", 42, 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				os.Setenv(tt.key, tt.envVal)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
			}
			got := envIntOrDefault(tt.key, tt.def)
			if got != tt.expected {
				t.Errorf("envIntOrDefault(%q, %d) = %d, want %d", tt.key, tt.def, got, tt.expected)
			}
		})
	}
}

func TestSplitNonEmpty(t *testing.T) {
	tests := []struct {
		input    string
		sep      string
		expected int
	}{
		{"a,b,c", ",", 3},
		{"a,,b, ,c", ",", 3},       // empty and whitespace-only removed
		{"", ",", 0},               // empty string
		{"  a , b  ", ",", 2},      // trimmed
		{"single", ",", 1},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := splitNonEmpty(tt.input, tt.sep)
			if len(got) != tt.expected {
				t.Errorf("splitNonEmpty(%q, %q) = %v (len=%d), want len=%d", tt.input, tt.sep, got, len(got), tt.expected)
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  hello  ", "hello"},
		{"\t\nhello\r\n", "hello"},
		{"", ""},
		{"no-trim", "no-trim"},
	}
	for _, tt := range tests {
		got := trimSpace(tt.input)
		if got != tt.expected {
			t.Errorf("trimSpace(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		s, sub string
		want   int
	}{
		{"hello world", "world", 6},
		{"hello", "x", -1},
		{"aaa", "a", 0},
		{"", "a", -1},
	}
	for _, tt := range tests {
		got := indexOf(tt.s, tt.sub)
		if got != tt.want {
			t.Errorf("indexOf(%q, %q) = %d, want %d", tt.s, tt.sub, got, tt.want)
		}
	}
}
