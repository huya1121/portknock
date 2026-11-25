package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPorts([]int{443, 22, 80, 80, 0, 70000}); err != nil { // dups + invalid dropped
		t.Fatal(err)
	}
	if err := s.AddFixed("203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := s.Grant("1.2.3.4", now); err != nil {
		t.Fatal(err)
	}

	// Reload from disk.
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	st := s2.Snapshot()
	if len(st.Ports) != 3 || st.Ports[0] != 22 || st.Ports[2] != 443 {
		t.Errorf("ports not sorted/deduped: %v", st.Ports)
	}
	if len(st.FixedIPs) != 1 || st.FixedIPs[0] != "203.0.113.5" {
		t.Errorf("fixed ips: %v", st.FixedIPs)
	}
	if len(st.Dynamic) != 1 || st.Dynamic[0].IP != "1.2.3.4" {
		t.Errorf("dynamic: %v", st.Dynamic)
	}
}

func TestTouchAndExpire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := NewStore(path)
	base := time.Now()
	// Two dynamic IPs granted now.
	s.Grant("1.1.1.1", base)
	s.Grant("2.2.2.2", base)

	window := 48 * time.Hour
	// 49h later: 1.1.1.1 is active (touched), 2.2.2.2 idle -> expires.
	later := base.Add(49 * time.Hour)
	expired, err := s.TouchAndExpire(map[string]bool{"1.1.1.1": true}, window, later)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0] != "2.2.2.2" {
		t.Fatalf("expected 2.2.2.2 expired, got %v", expired)
	}
	st := s.Snapshot()
	if len(st.Dynamic) != 1 || st.Dynamic[0].IP != "1.1.1.1" {
		t.Fatalf("expected only 1.1.1.1 to remain, got %v", st.Dynamic)
	}
	if !st.Dynamic[0].LastSeen.Equal(later) {
		t.Errorf("1.1.1.1 LastSeen not refreshed: %v", st.Dynamic[0].LastSeen)
	}
}

func TestRevokeDynamicIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := NewStore(path)
	s.Grant("1.1.1.1", time.Now())
	if err := s.RevokeDynamic("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDynamic("1.1.1.1"); err != nil { // second time: no-op
		t.Fatal(err)
	}
	if len(s.Snapshot().Dynamic) != 0 {
		t.Error("expected empty dynamic list")
	}
}

func TestSyncInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := NewStore(path)
	def := 2 * time.Minute

	// Unset -> falls back to default.
	if got := s.SyncIntervalOr(def); got != def {
		t.Errorf("unset: got %v, want %v", got, def)
	}

	// Normal value round-trips (and survives reload).
	if err := s.SetSyncInterval(30 * time.Second); err != nil {
		t.Fatal(err)
	}
	if got := s.SyncIntervalOr(def); got != 30*time.Second {
		t.Errorf("set 30s: got %v", got)
	}
	s2, _ := NewStore(path)
	if got := s2.SyncIntervalOr(def); got != 30*time.Second {
		t.Errorf("after reload: got %v", got)
	}

	// Below the 10s floor is clamped up, both on write and on read.
	if err := s.SetSyncInterval(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	if got := s.SyncIntervalOr(def); got != minSyncInterval {
		t.Errorf("clamp 3s: got %v, want %v", got, minSyncInterval)
	}
}
