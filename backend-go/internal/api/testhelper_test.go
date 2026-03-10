package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"macflow/internal/audit"
	"macflow/internal/config"
	"macflow/internal/health"
	"macflow/internal/runtime"
	"macflow/internal/state"
)

// mockRuntime implements RuntimeService for tests.
type mockRuntime struct {
	failCloseActive bool
	failCloseSince  int64
	failCloseReason string
}

func (m *mockRuntime) HotApply(_ bool) runtime.HotApplyResult {
	return runtime.HotApplyResult{}
}
func (m *mockRuntime) StopAll() runtime.HotApplyResult {
	return runtime.HotApplyResult{}
}
func (m *mockRuntime) GetFailCloseActive() bool   { return m.failCloseActive }
func (m *mockRuntime) GetFailCloseSince() int64   { return m.failCloseSince }
func (m *mockRuntime) GetFailCloseReason() string { return m.failCloseReason }

// newTestEnv initialises a temporary directory, config, store, monitor and
// returns an http.Handler built with NewTestRouter.
func newTestEnv(t *testing.T) (http.Handler, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	// write a minimal empty state file
	_ = os.WriteFile(filepath.Join(dir, "state.json"), []byte("{}"), 0o644)

	cfg := &config.Config{
		DataDir:    dir,
		WebDir:     dir,
		ListenPort: 8080,
		Version:    "test-1.0.0",
	}

	store, err := state.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	monitor := health.NewMonitor()
	auditLog := audit.NewLogger(dir)
	rt := &mockRuntime{}

	handler := NewTestRouter(cfg, store, monitor, rt, auditLog)
	return handler, cfg
}

// do is a convenience wrapper around httptest.
func do(t *testing.T, handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}
