package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// ── GET /api/status ───────────────────────────────────────────────────────────

func TestHandlerStatus_OK(t *testing.T) {
	h, _ := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/status", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/status: want 200, got %d (body: %s)", w.Code, w.Body)
	}
}

// ── GET /api/health ───────────────────────────────────────────────────────────

func TestHandlerHealth_ContainsVersion(t *testing.T) {
	h, cfg := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/health", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/health: want 200, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v, ok := body["version"]; !ok || v != cfg.Version {
		t.Errorf("want version=%q in /api/health, got %v", cfg.Version, v)
	}
}

// ── GET /api/system/info ──────────────────────────────────────────────────────

func TestHandlerSystemInfo_ContainsVersion(t *testing.T) {
	h, cfg := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/system/info", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/system/info: want 200, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, field := range []string{"uptime_sec", "memory_mb", "go_version", "version"} {
		if _, ok := body[field]; !ok {
			t.Errorf("/api/system/info missing field %q", field)
		}
	}
	if v := body["version"]; v != cfg.Version {
		t.Errorf("want version=%q, got %v", cfg.Version, v)
	}
}

// ── GET /api/nodes ────────────────────────────────────────────────────────────

func TestHandlerNodes_ReturnsArray(t *testing.T) {
	h, _ := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/nodes", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/nodes: want 200, got %d (body: %s)", w.Code, w.Body)
	}

	// Response should be a JSON array (possibly empty)
	var body interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body.([]interface{}); !ok {
		t.Errorf("GET /api/nodes: expected array response, got %T", body)
	}
}

// ── GET /api/devices ──────────────────────────────────────────────────────────

func TestHandlerDevices_ReturnsArray(t *testing.T) {
	h, _ := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/devices", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/devices: want 200, got %d (body: %s)", w.Code, w.Body)
	}

	var body interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body.([]interface{}); !ok {
		t.Errorf("GET /api/devices: expected array response, got %T", body)
	}
}

// ── POST /api/devices ─────────────────────────────────────────────────────────

func TestHandlerDeviceUpsert_BadBody(t *testing.T) {
	h, _ := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodPost, "/api/devices",
		bytes.NewBufferString(`{invalid json`))
	req.Header.Set("Content-Type", "application/json")
	w := do(t, h, req)

	if w.Code == http.StatusOK {
		t.Errorf("POST /api/devices with invalid JSON: expected non-200, got 200")
	}
}

// ── GET /api/logs (with q= search) ───────────────────────────────────────────

func TestHandlerLogs_QParam(t *testing.T) {
	h, _ := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/logs?q=test&lines=10", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/logs?q=test: want 200, got %d", w.Code)
	}

	// Response may be an array or object depending on implementation.
	var body interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET /api/logs?q=test: decode: %v", err)
	}
}

// ── GET /api/settings ─────────────────────────────────────────────────────────

func TestHandlerSettings_OK(t *testing.T) {
	h, _ := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/settings", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/settings: want 200, got %d (body: %s)", w.Code, w.Body)
	}
}

// ── GET /api/auth/status ──────────────────────────────────────────────────────

func TestHandlerAuthStatus_OK(t *testing.T) {
	h, _ := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/auth/status", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/status: want 200, got %d", w.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, f := range []string{"auth_enabled", "password_set", "valid_session"} {
		if _, ok := body[f]; !ok {
			t.Errorf("/api/auth/status missing field %q", f)
		}
	}
}

// ── GET /api/egress/router ────────────────────────────────────────────────────

func TestHandlerEgressRouter_OK(t *testing.T) {
	h, _ := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodGet, "/api/egress/router", nil)
	w := do(t, h, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/egress/router: want 200, got %d", w.Code)
	}
}
