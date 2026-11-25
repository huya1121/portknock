package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Dynamic is a user-submitted IP grant that is subject to the idle-expiry rule.
type Dynamic struct {
	IP       string    `json:"ip"`
	AddedAt  time.Time `json:"added_at"`
	LastSeen time.Time `json:"last_seen"`
}

// Child is a downstream portknock node this one fans grants out to. URL is the
// base address (e.g. "http://10.0.0.11:8080"); Key is that node's API key.
type Child struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

// State is the full persisted state of the service. It is the single source of
// truth; the firewall is reconciled to match it.
type State struct {
	Ports    []int     `json:"ports"`     // local-only open TCP ports (not synced)
	FixedIPs []string  `json:"fixed_ips"` // permanent whitelist
	Dynamic  []Dynamic `json:"dynamic"`   // user-submitted, idle-expiry applies
	Children []Child   `json:"children"`  // downstream nodes to fan grants out to
	// SyncPorts are open ports this node (as a center) distributes to all its
	// children; they are also opened locally. ReceivedPorts are open ports this
	// node (as a child) received from an upstream center. A single host can be
	// both, so the two are tracked separately. All three port lists are unioned
	// when reconciling the firewall.
	SyncPorts     []int `json:"sync_ports"`
	ReceivedPorts []int `json:"received_ports"`
	// SyncInterval is the keep-alive re-push interval to children, as a Go
	// duration string (e.g. "2m", "30s"). Empty = default. Configurable from the
	// admin UI; the syncer's keep-alive loop reads it each pass.
	SyncInterval string `json:"sync_interval"`
}

// Store guards State with a mutex and persists it atomically to disk.
type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

// NewStore loads state from path, creating an empty state if the file is absent.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			s.state = State{Ports: []int{}, FixedIPs: []string{}, Dynamic: []Dynamic{}}
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.state.Ports == nil {
		s.state.Ports = []int{}
	}
	if s.state.FixedIPs == nil {
		s.state.FixedIPs = []string{}
	}
	if s.state.Dynamic == nil {
		s.state.Dynamic = []Dynamic{}
	}
	if s.state.Children == nil {
		s.state.Children = []Child{}
	}
	if s.state.SyncPorts == nil {
		s.state.SyncPorts = []int{}
	}
	if s.state.ReceivedPorts == nil {
		s.state.ReceivedPorts = []int{}
	}
	return s, nil
}

// snapshot returns a deep copy of the current state. Caller must NOT hold mu.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.copyLocked()
}

func (s *Store) copyLocked() State {
	cp := State{
		Ports:         append([]int(nil), s.state.Ports...),
		FixedIPs:      append([]string(nil), s.state.FixedIPs...),
		Dynamic:       append([]Dynamic(nil), s.state.Dynamic...),
		Children:      append([]Child(nil), s.state.Children...),
		SyncPorts:     append([]int(nil), s.state.SyncPorts...),
		ReceivedPorts: append([]int(nil), s.state.ReceivedPorts...),
		SyncInterval:  s.state.SyncInterval,
	}
	return cp
}

// persistLocked writes state to disk atomically. Caller must hold mu.
func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeded
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// --- Mutating operations. Each persists and returns an error on failure. ---

// cleanPorts dedupes, validates (1..65535) and sorts a port list.
func cleanPorts(ports []int) []int {
	seen := map[int]bool{}
	clean := []int{}
	for _, p := range ports {
		if p < 1 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		clean = append(clean, p)
	}
	sort.Ints(clean)
	return clean
}

// SetPorts replaces the local-only open port list (deduped, sorted, validated).
func (s *Store) SetPorts(ports []int) error {
	clean := cleanPorts(ports)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Ports = clean
	return s.persistLocked()
}

// SetSyncPorts replaces the list of open ports this node distributes to children.
func (s *Store) SetSyncPorts(ports []int) error {
	clean := cleanPorts(ports)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.SyncPorts = clean
	return s.persistLocked()
}

// SetReceivedPorts replaces the list of open ports received from an upstream
// center (child side). Full-list replace = the center's declarative push wins.
func (s *Store) SetReceivedPorts(ports []int) error {
	clean := cleanPorts(ports)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.ReceivedPorts = clean
	return s.persistLocked()
}

// minSyncInterval is the floor for the child keep-alive interval: anything lower
// would hammer children / CPU without benefit (grants have a 48h expiry window).
const minSyncInterval = 10 * time.Second

// SetSyncInterval persists the child keep-alive interval, clamped to >= 10s.
func (s *Store) SetSyncInterval(d time.Duration) error {
	if d < minSyncInterval {
		d = minSyncInterval
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.SyncInterval = d.String()
	return s.persistLocked()
}

// SyncIntervalOr returns the configured sync interval, falling back to def when
// unset or unparseable, and never returning less than minSyncInterval.
func (s *Store) SyncIntervalOr(def time.Duration) time.Duration {
	s.mu.Lock()
	raw := s.state.SyncInterval
	s.mu.Unlock()
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		d = def
	}
	if d < minSyncInterval {
		d = minSyncInterval
	}
	return d
}

// AddChild adds (or updates the key of) a downstream node, keyed by URL.
func (s *Store) AddChild(url, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Children {
		if s.state.Children[i].URL == url {
			s.state.Children[i].Key = key
			return s.persistLocked()
		}
	}
	s.state.Children = append(s.state.Children, Child{URL: url, Key: key})
	return s.persistLocked()
}

// RemoveChild removes a downstream node by URL (idempotent).
func (s *Store) RemoveChild(url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.Children[:0:0]
	for _, c := range s.state.Children {
		if c.URL != url {
			out = append(out, c)
		}
	}
	s.state.Children = out
	return s.persistLocked()
}

// AddFixed adds a permanent IP (idempotent).
func (s *Store) AddFixed(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.state.FixedIPs {
		if existing == ip {
			return s.persistLocked()
		}
	}
	s.state.FixedIPs = append(s.state.FixedIPs, ip)
	sort.Strings(s.state.FixedIPs)
	return s.persistLocked()
}

// RemoveFixed removes a permanent IP (idempotent).
func (s *Store) RemoveFixed(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.FixedIPs[:0:0]
	for _, existing := range s.state.FixedIPs {
		if existing != ip {
			out = append(out, existing)
		}
	}
	s.state.FixedIPs = out
	return s.persistLocked()
}

// Grant adds or refreshes a dynamic IP, setting LastSeen to now. added reports
// whether this was a new grant (true) vs. a refresh of an existing one (false),
// so callers can skip the (idempotent) firewall call on keep-alive refreshes.
func (s *Store) Grant(ip string, now time.Time) (added bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Dynamic {
		if s.state.Dynamic[i].IP == ip {
			s.state.Dynamic[i].LastSeen = now
			return false, s.persistLocked()
		}
	}
	s.state.Dynamic = append(s.state.Dynamic, Dynamic{IP: ip, AddedAt: now, LastSeen: now})
	return true, s.persistLocked()
}

// RevokeDynamic removes a dynamic IP (idempotent).
func (s *Store) RevokeDynamic(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.Dynamic[:0:0]
	for _, d := range s.state.Dynamic {
		if d.IP != ip {
			out = append(out, d)
		}
	}
	s.state.Dynamic = out
	return s.persistLocked()
}

// TouchAndExpire updates LastSeen for any dynamic IP present in active (set of
// IPs with live connections to whitelisted ports), then removes dynamic IPs idle
// longer than window. Returns the list of expired IPs so the caller can revoke
// their firewall rules. Persists if anything changed.
func (s *Store) TouchAndExpire(active map[string]bool, window time.Duration, now time.Time) (expired []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	kept := s.state.Dynamic[:0:0]
	for _, d := range s.state.Dynamic {
		if active[d.IP] {
			if !d.LastSeen.Equal(now) {
				d.LastSeen = now
				changed = true
			}
		}
		if now.Sub(d.LastSeen) > window {
			expired = append(expired, d.IP)
			changed = true
			continue
		}
		kept = append(kept, d)
	}
	s.state.Dynamic = kept
	if changed {
		if err := s.persistLocked(); err != nil {
			return expired, err
		}
	}
	return expired, nil
}
