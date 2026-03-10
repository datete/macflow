// Package config handles application configuration from environment variables.
package config

import (
	"os"
	"path/filepath"
	"strconv"
)

// Config holds all application configuration.
type Config struct {
	// DataDir is the path for state.json, auth.json, audit.log.
	DataDir string

	// WebDir is the path for static web files (index.html, captive.html).
	WebDir string

	// ListenPort is the HTTP server port.
	ListenPort int

	// ClashAPI is the sing-box Clash-compatible API address.
	ClashAPI string

	// MixedProxy is the local mixed (HTTP+SOCKS) proxy address.
	MixedProxy string

	// BindAddr is the address to bind the HTTP server to.
	BindAddr string

	// CORSOrigins is a list of allowed CORS origins.
	CORSOrigins []string

	// GitHubRepo for update checks (owner/repo format).
	GitHubRepo string

	// Version is the application version, injected from main via ldflags.
	Version string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	root := findRoot()
	cfg := &Config{
		DataDir:    envOrDefault("MACFLOW_DATA_DIR", filepath.Join(root, "data")),
		WebDir:     envOrDefault("MACFLOW_WEB_DIR", filepath.Join(root, "web")),
		ListenPort: envIntOrDefault("MACFLOW_LISTEN_PORT", 18080),
		BindAddr:   envOrDefault("MACFLOW_BIND", "0.0.0.0"),
		ClashAPI:   envOrDefault("MACFLOW_CLASH_API", "http://127.0.0.1:9090"),
		MixedProxy: envOrDefault("MACFLOW_MIXED_PROXY", "http://127.0.0.1:1080"),
		GitHubRepo: envOrDefault("MACFLOW_GITHUB_REPO", ""),
	}

	if origins := os.Getenv("MACFLOW_CORS_ORIGINS"); origins != "" {
		for _, o := range splitNonEmpty(origins, ",") {
			cfg.CORSOrigins = append(cfg.CORSOrigins, o)
		}
	} else {
		// Secure defaults for local network access
		cfg.CORSOrigins = []string{
			"http://192.168.1.1:18080",
			"http://192.168.1.1",
			"http://localhost:18080",
			"http://localhost",
			"http://127.0.0.1:18080",
			"http://127.0.0.1",
		}
	}

	return cfg
}

func findRoot() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(filepath.Dir(exe))
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func splitNonEmpty(s, sep string) []string {
	var result []string
	for _, part := range splitString(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitString(s, sep string) []string {
	if sep == "" {
		return []string{s}
	}
	var parts []string
	for {
		i := indexOf(s, sep)
		if i < 0 {
			parts = append(parts, s)
			break
		}
		parts = append(parts, s[:i])
		s = s[i+len(sep):]
	}
	return parts
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
