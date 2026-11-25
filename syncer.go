package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// syncHeader marks a request as a node-to-node sync push, so the receiving node
// grants locally but does NOT forward it again (one-hop cap = loop-safe).
const syncHeader = "X-Portknock-Sync"

// ChildStatus is the outcome of the last push to a child node, shown in admin.
type ChildStatus struct {
	OK   bool      // last push succeeded
	When time.Time // when that last push happened (zero = never tried)
	Err  string    // short error if the last push failed
}

// Syncer fans dynamic grants out to downstream ("child") portknock nodes by
// calling their /api/grant endpoint. It is best-effort: failures are logged,
// never block the local grant, and get another chance on the next janitor
// keep-alive pass. It also records each child's last-push result for the UI.
type Syncer struct {
	store  *Store
	client *http.Client
	mu     sync.Mutex
	status map[string]ChildStatus // child URL -> last push result (outbound)
	// upstreams records who has pushed sync grants TO this node (inbound), so a
	// node that was added as someone's child can show its upstream center(s) in
	// the admin UI. Keyed by the pushing node's IP -> last time it pushed.
	upstreams map[string]time.Time
}

func NewSyncer(store *Store) *Syncer {
	return &Syncer{
		store:     store,
		upstreams: map[string]time.Time{},
		// Node-to-node sync skips TLS cert verification on purpose: every node
		// serves a self-signed cert whose SANs cover only its local interface
		// IPs (not NAT/public IPs or hostnames), so chain verification can never
		// succeed between nodes. Authentication is provided by the per-child API
		// key (Bearer token), not by the certificate — same tradeoff as curl -k.
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see comment above
			},
		},
		status: map[string]ChildStatus{},
	}
}

// childBase normalizes a child URL the admin entered: strips trailing slashes
// and a trailing "/api/grant" (a common copy-paste from the API card), so we
// never build "…/api/grant/api/grant". Returns the base origin (scheme+host).
func childBase(raw string) string {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	u = strings.TrimSuffix(u, "/api/grant")
	return strings.TrimRight(u, "/")
}

// Status returns a copy of the last-push result for each child URL.
func (s *Syncer) Status() map[string]ChildStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]ChildStatus, len(s.status))
	for k, v := range s.status {
		out[k] = v
	}
	return out
}

// RecordUpstream notes that node `ip` just pushed a sync grant to us. Called
// from /api/grant when the request carries the sync header, so this node can
// show which center(s) it is a child of. Keeps only the latest time per IP.
func (s *Syncer) RecordUpstream(ip string) {
	if ip == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreams[ip] = time.Now()
}

// Upstreams returns a copy of the upstream centers (IP -> last push time) that
// have synced grants to this node.
func (s *Syncer) Upstreams() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]time.Time, len(s.upstreams))
	for k, v := range s.upstreams {
		out[k] = v
	}
	return out
}

// record stores the outcome of a push to url.
func (s *Syncer) record(url string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := ChildStatus{OK: err == nil, When: time.Now()}
	if err != nil {
		st.Err = err.Error()
	}
	s.status[url] = st
}

// pushOne grants ip on a single child node. Returns nil on a 2xx "granted".
func (s *Syncer) pushOne(ctx context.Context, c Child, ip string) error {
	body, _ := json.Marshal(map[string]string{"ip": ip})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, childBase(c.URL)+"/api/grant", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(syncHeader, "1") // tell the child not to forward again
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	// Drain + close so net/http can reuse the keep-alive connection next pass.
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("child %s returned HTTP %d", c.URL, resp.StatusCode)
	}
	return nil
}

// pushToChildren pushes every ip to every child concurrently and waits for all
// of them, then lets its context expire. It runs in its own goroutine (started
// by FanOut/FanOutAll), so HTTP latency never blocks the grant handler or the
// janitor. The context is cancelled only AFTER every push returns — cancelling
// earlier (the classic defer-cancel bug) would abort all in-flight requests.
func (s *Syncer) pushToChildren(children []Child, ips []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, c := range children {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Push all IPs to this child in sequence; record one status for the
			// child (fails if any IP push fails — usually means it's unreachable).
			var firstErr error
			for _, ip := range ips {
				if err := s.pushOne(ctx, c, ip); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					log.Printf("sync: push %s -> %s: %v", ip, c.URL, err)
				}
			}
			s.record(c.URL, firstErr)
			if firstErr == nil {
				log.Printf("sync: pushed %d IP(s) -> %s", len(ips), c.URL)
			}
		}()
	}
	wg.Wait()
}

// pushPortsOne sends the full sync-port list to a single child's /api/ports.
// Like pushOne it skips TLS verification and carries the sync header + API key.
func (s *Syncer) pushPortsOne(ctx context.Context, c Child, ports []int) error {
	body, _ := json.Marshal(map[string][]int{"ports": ports})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, childBase(c.URL)+"/api/ports", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(syncHeader, "1")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("child %s returned HTTP %d", c.URL, resp.StatusCode)
	}
	return nil
}

// FanOutPorts pushes the full sync-port list to every child concurrently in the
// background. Declarative/full-list: a child replaces its received ports with
// exactly this set, so a port removed at the center closes on the child too.
func (s *Syncer) FanOutPorts() {
	if !s.syncingEnabled() {
		return
	}
	st := s.store.Snapshot()
	if len(st.Children) == 0 {
		return
	}
	ports := append([]int(nil), st.SyncPorts...)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		for _, c := range st.Children {
			c := c
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := s.pushPortsOne(ctx, c, ports); err != nil {
					log.Printf("sync: push ports -> %s: %v", c.URL, err)
				} else {
					log.Printf("sync: pushed %d port(s) -> %s", len(ports), c.URL)
				}
			}()
		}
		wg.Wait()
	}()
}

// RunKeepAlive periodically re-pushes the full whitelist (IPs + ports) to all
// children so they don't expire grants on their own idle timer. The interval is
// read from the store each pass, so changing it in the admin UI takes effect on
// the next tick without a restart. Runs until stop is closed. Does one immediate
// pass on start. defInterval is the fallback when none is configured.
func (s *Syncer) RunKeepAlive(stop <-chan struct{}, defInterval time.Duration) {
	s.FanOutAll() // immediate first pass
	timer := time.NewTimer(s.store.SyncIntervalOr(defInterval))
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			s.FanOutAll()
			timer.Reset(s.store.SyncIntervalOr(defInterval)) // re-read: picks up admin changes
		}
	}
}

// hasUpstream reports whether any upstream center has ever pushed to this node.
func (s *Syncer) hasUpstream() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.upstreams) > 0
}

// EffectiveMode resolves the node's role, combining the admin's explicit override
// (store.NodeMode) with auto-detection: "center" or "child". In auto mode ("")
// the node is a child once some upstream has pushed to it, else a center.
func (s *Syncer) EffectiveMode() string {
	switch s.store.Snapshot().NodeMode {
	case "center":
		return "center"
	case "child":
		return "child"
	default: // auto
		if s.hasUpstream() {
			return "child"
		}
		return "center"
	}
}

// syncingEnabled reports whether this node should fan out to children. A node in
// (effective) child mode stops all outbound sync — it is a leaf, not a relay.
func (s *Syncer) syncingEnabled() bool {
	return s.EffectiveMode() == "center"
}

// FanOut pushes one ip to all configured children in the background.
func (s *Syncer) FanOut(ip string) {
	if !s.syncingEnabled() {
		return
	}
	children := s.store.Snapshot().Children
	if len(children) == 0 {
		return
	}
	go s.pushToChildren(children, []string{ip})
}

// FanOutAll re-pushes every whitelisted IP (dynamic + fixed) to all children,
// so children keep them alive (the janitor calls this each pass). Snapshots
// once and does a single batched background fan-out.
func (s *Syncer) FanOutAll() {
	if !s.syncingEnabled() {
		return
	}
	st := s.store.Snapshot()
	if len(st.Children) == 0 {
		return
	}
	ips := make([]string, 0, len(st.Dynamic)+len(st.FixedIPs))
	for _, d := range st.Dynamic {
		ips = append(ips, d.IP)
	}
	ips = append(ips, st.FixedIPs...)
	if len(ips) > 0 {
		go s.pushToChildren(st.Children, ips)
	}
	// Also re-push the sync-port list each pass so children stay converged and
	// a removed port is re-asserted as closed (full-list/declarative).
	s.FanOutPorts()
}
