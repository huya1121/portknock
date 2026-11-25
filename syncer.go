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

// Syncer fans dynamic grants out to downstream ("child") portknock nodes by
// calling their /api/grant endpoint. It is best-effort: failures are logged,
// never block the local grant, and get another chance on the next janitor
// keep-alive pass.
type Syncer struct {
	store  *Store
	client *http.Client
}

func NewSyncer(store *Store) *Syncer {
	return &Syncer{
		store:  store,
		client: &http.Client{Timeout: 10 * time.Second},
	}
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
		for _, ip := range ips {
			wg.Add(1)
			c, ip := c, ip
			go func() {
				defer wg.Done()
				if err := s.pushOne(ctx, c, ip); err != nil {
					log.Printf("sync: push %s -> %s: %v", ip, c.URL, err)
				} else {
					log.Printf("sync: pushed %s -> %s", ip, c.URL)
				}
			}()
		}
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

// FanOutAll re-pushes every currently-granted dynamic IP to all children (the
// janitor calls this each pass so children keep the IPs alive). Snapshots once
// and does a single batched background fan-out.
func (s *Syncer) FanOutAll() {
	st := s.store.Snapshot()
	if len(st.Children) == 0 || len(st.Dynamic) == 0 {
		return
	}
	ips := make([]string, 0, len(st.Dynamic))
	for _, d := range st.Dynamic {
		ips = append(ips, d.IP)
	}
	go s.pushToChildren(st.Children, ips)
}

