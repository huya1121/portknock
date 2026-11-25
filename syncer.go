package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	status map[string]ChildStatus // child URL -> last push result
}

func NewSyncer(store *Store) *Syncer {
	return &Syncer{
		store:  store,
		client: &http.Client{Timeout: 10 * time.Second},
		status: map[string]ChildStatus{},
	}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/api/grant", bytes.NewReader(body))
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

// FanOut pushes one ip to all configured children in the background.
func (s *Syncer) FanOut(ip string) {
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
	st := s.store.Snapshot()
	if len(st.Children) == 0 {
		return
	}
	ips := make([]string, 0, len(st.Dynamic)+len(st.FixedIPs))
	for _, d := range st.Dynamic {
		ips = append(ips, d.IP)
	}
	ips = append(ips, st.FixedIPs...)
	if len(ips) == 0 {
		return
	}
	go s.pushToChildren(st.Children, ips)
}

