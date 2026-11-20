package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"time"
)

// conntrackPaths are tried in order; the first readable one is used.
var conntrackPaths = []string{
	"/proc/net/nf_conntrack",
	"/proc/net/ip_conntrack",
}

// Janitor periodically refreshes LastSeen for active dynamic IPs (from the kernel
// conntrack table) and expires IPs idle longer than the configured window.
type Janitor struct {
	store    *Store
	fw       *Firewall
	poll     time.Duration
	window   time.Duration
	nowFn    func() time.Time
	hasConn  bool // whether a conntrack source is readable
}

func NewJanitor(store *Store, fw *Firewall, poll, window time.Duration) *Janitor {
	j := &Janitor{store: store, fw: fw, poll: poll, window: window, nowFn: time.Now}
	j.hasConn = conntrackReadable()
	if !j.hasConn {
		log.Printf("warning: no readable conntrack table (%v); dynamic IPs will expire %s after grant/last refresh regardless of activity",
			conntrackPaths, window)
	}
	return j
}

func conntrackReadable() bool {
	for _, p := range conntrackPaths {
		if f, err := os.Open(p); err == nil {
			f.Close()
			return true
		}
	}
	return false
}

// Run blocks, ticking every poll interval until the stop channel is closed.
func (j *Janitor) Run(stop <-chan struct{}) {
	t := time.NewTicker(j.poll)
	defer t.Stop()
	j.tick() // run once immediately
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			j.tick()
		}
	}
}

func (j *Janitor) tick() {
	st := j.store.Snapshot()
	now := j.nowFn()

	active := map[string]bool{}
	if j.hasConn {
		if data, err := readFirst(conntrackPaths); err == nil {
			dyn := map[string]bool{}
			for _, d := range st.Dynamic {
				dyn[d.IP] = true
			}
			active = activeIPs(data, dyn)
		} else {
			log.Printf("janitor: read conntrack: %v", err)
		}
	}

	expired, err := j.store.TouchAndExpire(active, j.window, now)
	if err != nil {
		log.Printf("janitor: persist: %v", err)
	}
	for _, ip := range expired {
		log.Printf("janitor: expiring idle dynamic IP %s", ip)
		if err := j.fw.RevokeIP(ip); err != nil {
			log.Printf("janitor: revoke %s: %v", ip, err)
		}
	}
}

func readFirst(paths []string) (string, error) {
	var lastErr error
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			return string(data), nil
		}
		lastErr = err
	}
	return "", lastErr
}

// activeIPs parses conntrack text and returns the set of source IPs present in
// the dyn set that have any live connection. Since a dynamic IP is granted
// access to all ports, any connection from it counts as activity (no port
// filtering).
//
// A conntrack line contains space-separated key=value tokens, e.g.:
//   ipv4 2 tcp 6 431999 ESTABLISHED src=1.2.3.4 dst=10.0.0.1 sport=5000 dport=80 ...
// The first src= on the line is the originating source (the client connecting in).
func activeIPs(conntrack string, dyn map[string]bool) map[string]bool {
	active := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(conntrack))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		src := firstValue(line, "src=")
		if src != "" && dyn[src] {
			active[src] = true
		}
	}
	return active
}

// firstValue returns the value following the first occurrence of key (e.g.
// "src=") on the line, up to the next space.
func firstValue(line, key string) string {
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key):]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		return rest[:sp]
	}
	return rest
}
