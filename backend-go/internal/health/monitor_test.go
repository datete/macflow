package health

import (
	"testing"

	"macflow/internal/state"
)

func TestComputeOverall(t *testing.T) {
	tests := []struct {
		name     string
		checks   map[string]CheckResult
		expected string
	}{
		{
			"all ok",
			map[string]CheckResult{
				"a": {Status: "ok"},
				"b": {Status: "ok"},
			},
			"ok",
		},
		{
			"one critical",
			map[string]CheckResult{
				"a": {Status: "ok"},
				"b": {Status: "critical"},
			},
			"critical",
		},
		{
			"one warn no critical",
			map[string]CheckResult{
				"a": {Status: "ok"},
				"b": {Status: "warn"},
			},
			"warn",
		},
		{
			"critical beats warn",
			map[string]CheckResult{
				"a": {Status: "warn"},
				"b": {Status: "critical"},
			},
			"critical",
		},
		{
			"empty checks",
			map[string]CheckResult{},
			"ok",
		},
		{
			"unknown status",
			map[string]CheckResult{
				"a": {Status: "unknown"},
			},
			"degraded",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeOverall(tt.checks)
			if got != tt.expected {
				t.Errorf("computeOverall() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestComputeNodeHealthScore(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name       string
		latency    *int
		speed      float64
		failures   int
		enabled    bool
		wantScore  int
		wantStatus string
	}{
		{"disabled node", intPtr(0), 0, 0, false, 0, "disabled"},
		{"nil latency, no speed", nil, 0, 0, true, 72, "healthy"},       // 42+30
		{"fast low speed", intPtr(50), 0, 0, true, 85, "healthy"},       // 55+30
		{"fast high speed", intPtr(50), 60, 0, true, 100, "healthy"},    // 55+45=100
		{"medium latency", intPtr(100), 10, 0, true, 80, "healthy"},     // 45+35 (speed>=5)
		{"high latency", intPtr(200), 0, 0, true, 62, "degraded"},      // 32+30
		{"very high latency", intPtr(500), 0, 0, true, 45, "degraded"}, // 15+30
		{"failures reduce score", intPtr(50), 0, 3, true, 61, "degraded"}, // 55+30-24
		{"negative latency", intPtr(-1), 0, 0, true, 35, "unhealthy"},  // 5+30
		{"many failures = 0", intPtr(500), 0, 10, true, 0, "unhealthy"}, // 15+30-80, capped at 0
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, status := ComputeNodeHealthScore(tt.latency, tt.speed, tt.failures, tt.enabled)
			if score != tt.wantScore {
				t.Errorf("score = %d, want %d", score, tt.wantScore)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %q, want %q", status, tt.wantStatus)
			}
		})
	}
}

func TestNodeSortKey(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	// Higher score → lower sort key (negated)
	n1 := state.Node{Tag: "fast", HealthScore: 90, Latency: intPtr(50)}
	n2 := state.Node{Tag: "slow", HealthScore: 30, Latency: intPtr(300)}
	n3 := state.Node{Tag: "mid", HealthScore: 90, Latency: intPtr(100)}

	s1, l1, _ := NodeSortKey(n1)
	s2, l2, _ := NodeSortKey(n2)
	s3, l3, _ := NodeSortKey(n3)

	// n1 should sort before n2 (higher score)
	if s1 > s2 {
		t.Errorf("fast (-90) should sort before slow (-30)")
	}

	// n1 and n3 have same score, n1 should sort before n3 (lower latency)
	if s1 != s3 {
		t.Errorf("same score should have same first key")
	}
	if l1 > l3 {
		t.Errorf("lower latency should sort first: %d vs %d", l1, l3)
	}

	// nil latency → 9000
	n4 := state.Node{Tag: "nolatency", HealthScore: 50}
	_, l4, _ := NodeSortKey(n4)
	if l4 != 9000 {
		t.Errorf("nil latency should give 9000, got %d", l4)
	}
	_ = l2 // used
}

func TestFormatChecksSummary(t *testing.T) {
	checks := map[string]CheckResult{
		"a": {Status: "ok"},
	}
	summary := FormatChecksSummary(checks)
	if summary != "a=ok" {
		t.Errorf("unexpected summary: %q", summary)
	}
}

func TestMonitorLifecycle(t *testing.T) {
	m := NewMonitor()

	if m.OverallStatus != "unknown" {
		t.Errorf("initial status should be unknown, got %q", m.OverallStatus)
	}

	// Apply some results
	checks := map[string]CheckResult{
		"singbox": {Status: "ok", Message: "running"},
		"tun":     {Status: "ok", Message: "up"},
	}
	m.ApplyResults(checks, "ok")

	gotChecks, _, overall, _ := m.GetState()
	if overall != "ok" {
		t.Errorf("overall should be ok, got %q", overall)
	}
	if len(gotChecks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(gotChecks))
	}
	if m.GetProbeCycle() != 1 {
		t.Errorf("probe cycle should be 1, got %d", m.GetProbeCycle())
	}
}

func TestAckAlert(t *testing.T) {
	m := NewMonitor()
	m.Alerts = []Alert{
		{ID: "alert-1", Status: "active"},
		{ID: "alert-2", Status: "active"},
	}

	if !m.AckAlert("alert-1") {
		t.Error("AckAlert should return true for existing alert")
	}
	if m.AckAlert("nonexistent") {
		t.Error("AckAlert should return false for missing alert")
	}

	_, alerts, _, _ := m.GetState()
	for _, a := range alerts {
		if a.ID == "alert-1" && a.Status != "acknowledged" {
			t.Error("alert-1 should be acknowledged")
		}
	}
}
