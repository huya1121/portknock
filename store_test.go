ckage main

import (
	"path/filepath"
	"testing"
	"time"
)

// newTestSyncer builds a Syncer backed by a temp store (no network use here).
func newTestSyncer(t *testing.T) *Syncer {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return NewSyncer(st)
}

func TestUpstreamTTLPrune(t *testing.T) {
	s := newTestSyncer(t)

	// Fresh upstream shows up.
	s.RecordUpstream("10.0.0.1")
	if ups := s.Upstreams(); len(ups) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(ups))
	}
	if !s.hasUpstream() {
		t.Error("hasUpstream should be true with a fresh upstream")
	}

	// Backdate it past the TTL -> should be pruned on next read.
	s.mu.Lock()
	s.upstreams["10.0.0.1"] = time.Now().Add(-upstreamTTL - time.Minute)
	s.mu.Unlock()

	if ups := s.Upstreams(); len(ups) != 0 {
		t.Errorf("stale upstream should be pruned, got %v", ups)
	}
	if s.hasUpstream() {
		t.Error("hasUpstream should be false after the upstream went stale")
	}

	// And it should be gone from the backing map, not just the returned copy.
	s.mu.Lock()
	n := len(s.upstreams)
	s.mu.Unlock()
	if n != 0 {
		t.Errorf("stale entry should be deleted from the map, %d remain", n)
	}
}

func TestUpstreamFreshKept(t *testing.T) {
	s := newTestSyncer(t)
	s.RecordUpstream("10.0.0.2")
	// Backdate but still within TTL.
	s.mu.Lock()
	s.upstreams["10.0.0.2"] = time.Now().Add(-upstreamTTL + 5*time.Minute)
	s.mu.Unlock()
	if ups := s.Upstreams(); len(ups) != 1 {
		t.Errorf("upstream within TTL should be kept, got %v", ups)
	}
}

