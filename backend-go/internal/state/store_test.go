package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestInitialState(t *testing.T) {
	st := InitialState()

	if st.Enabled {
		t.Error("InitialState should have Enabled=false")
	}
	if st.DefaultPolicy != "whitelist" {
		t.Errorf("expected default_policy=whitelist, got %q", st.DefaultPolicy)
	}
	if st.FailurePolicy != "fail-close" {
		t.Errorf("expected failure_policy=fail-close, got %q", st.FailurePolicy)
	}
	if st.DNS.EnforceRedirectPort != 6053 {
		t.Errorf("expected dns port 6053, got %d", st.DNS.EnforceRedirectPort)
	}
	if !st.DNS.BlockDOHDOQ {
		t.Error("expected block_doh_doq=true")
	}
	if len(st.DNS.Servers) != 2 {
		t.Errorf("expected 2 DNS servers, got %d", len(st.DNS.Servers))
	}
	if st.XUISourceList == nil {
		t.Error("xui_sources should be initialized (not nil)")
	}
	if st.Nodes == nil || st.Devices == nil || st.Subscriptions == nil {
		t.Error("slices should be initialized (not nil)")
	}
}

func TestNewStoreCreatesDefaultState(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	st := store.Read()
	if st.DefaultPolicy != "whitelist" {
		t.Errorf("expected default policy whitelist, got %q", st.DefaultPolicy)
	}

	// Check file was created
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("state.json not created: %v", err)
	}
	if len(data) == 0 {
		t.Error("state.json is empty")
	}
}

func TestNewStoreLoadsExisting(t *testing.T) {
	dir := t.TempDir()
	state := `{"enabled":true,"default_policy":"block","failure_policy":"fail-open","dns":{"enforce_redirect_port":53},"xui_sources":[],"subscriptions":[],"nodes":[],"devices":[]}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(state), 0o644); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	st := store.Read()
	if !st.Enabled {
		t.Error("expected enabled=true from loaded state")
	}
	if st.DefaultPolicy != "block" {
		t.Errorf("expected policy=block, got %q", st.DefaultPolicy)
	}
}

func TestStoreUpdate(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)

	err := store.Update(func(st *State) {
		st.Enabled = true
		st.DefaultPolicy = "block"
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	st := store.Read()
	if !st.Enabled || st.DefaultPolicy != "block" {
		t.Errorf("Update not applied: enabled=%v policy=%s", st.Enabled, st.DefaultPolicy)
	}

	// Verify persisted to disk
	data, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	var persisted State
	json.Unmarshal(data, &persisted)
	if !persisted.Enabled {
		t.Error("state not persisted to disk")
	}
}

func TestStoreReadReturnsCopy(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)

	store.Update(func(st *State) {
		st.Nodes = append(st.Nodes, Node{Tag: "node1", Type: "ss"})
	})

	// Mutating the returned copy should not affect the store
	copy := store.Read()
	copy.Nodes = append(copy.Nodes, Node{Tag: "mutated"})

	original := store.Read()
	if len(original.Nodes) != 1 {
		t.Errorf("Read() copy was mutated: expected 1 node, got %d", len(original.Nodes))
	}
}

func TestNextMark(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)

	// Initial mark should be 0x100 (256)
	m1 := store.NextMark()
	if m1 != 0x100 {
		t.Errorf("expected first mark 0x100 (256), got 0x%x (%d)", m1, m1)
	}

	// After adding a device with mark 0x100, next should be 0x101
	store.Update(func(st *State) {
		st.Devices = append(st.Devices, Device{MAC: "AA:BB:CC:DD:EE:FF", Mark: 0x100})
	})
	m2 := store.NextMark()
	if m2 != 0x101 {
		t.Errorf("expected next mark 0x101, got 0x%x", m2)
	}

	// With gaps: device at 0x105 → next should be 0x106
	store.Update(func(st *State) {
		st.Devices = append(st.Devices, Device{MAC: "11:22:33:44:55:66", Mark: 0x105})
	})
	m3 := store.NextMark()
	if m3 != 0x106 {
		t.Errorf("expected next mark 0x106, got 0x%x", m3)
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	// 50 concurrent writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := store.Update(func(st *State) {
				st.LastSync = int64(idx)
			}); err != nil {
				errs <- err
			}
		}(i)
	}

	// 50 concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.Read()
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent error: %v", err)
	}
}

func TestStateJSONRoundTrip(t *testing.T) {
	original := InitialState()
	original.Enabled = true
	original.Nodes = append(original.Nodes, Node{
		Tag: "test", Type: "shadowsocks", Server: "1.2.3.4", ServerPort: 443,
		Method: "aes-128-gcm", Password: "secret", Enabled: true,
	})
	original.Devices = append(original.Devices, Device{
		MAC: "AA:BB:CC:DD:EE:FF", Name: "Phone", NodeTag: "test",
		Managed: true, Mark: 0x100,
	})

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded State
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Nodes[0].Tag != "test" || decoded.Devices[0].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Error("JSON round-trip lost data")
	}
}

func TestStoreCorruptFile(t *testing.T) {
	dir := t.TempDir()
	// Write corrupt JSON
	os.WriteFile(filepath.Join(dir, "state.json"), []byte("{invalid json"), 0o644)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore should recover from corrupt file: %v", err)
	}

	st := store.Read()
	if st.DefaultPolicy != "whitelist" {
		t.Error("should have initialized with defaults on corrupt file")
	}
}
