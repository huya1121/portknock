package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ghRepo is the GitHub repo to check for new releases.
const ghRepo = "huya1121/portknock"

// updateCheckInterval is how often the background checker polls GitHub.
const updateCheckInterval = 6 * time.Hour

// UpdateChecker periodically asks GitHub for the latest release tag and caches
// it, so the admin page can show an "update available" hint without blocking on
// a network call per request. Best-effort: network/API failures are ignored and
// the last known value is kept.
type UpdateChecker struct {
	client  *http.Client
	mu      sync.Mutex
	latest  string    // latest release tag seen (e.g. "v1.2.0"), "" = unknown
	checked time.Time // when we last successfully fetched
}

func NewUpdateChecker() *UpdateChecker {
	return &UpdateChecker{client: &http.Client{Timeout: 10 * time.Second}}
}

// Run polls GitHub every updateCheckInterval until stop is closed. One immediate
// check on start (after a short delay so startup isn't slowed).
func (u *UpdateChecker) Run(stop <-chan struct{}) {
	timer := time.NewTimer(30 * time.Second) // first check shortly after boot
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			u.checkOnce()
			timer.Reset(updateCheckInterval)
		}
	}
}

func (u *UpdateChecker) checkOnce() {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+ghRepo+"/releases/latest", nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "portknock")
	resp, err := u.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return
	}
	tag := strings.TrimSpace(body.TagName)
	if tag == "" {
		return
	}
	u.mu.Lock()
	u.latest = tag
	u.checked = time.Now()
	u.mu.Unlock()
}

// Latest returns the cached latest release tag ("" if not fetched yet).
func (u *UpdateChecker) Latest() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.latest
}

// UpdateAvailable reports whether the cached latest release is newer than the
// running version. Returns (available, latestTag). Unknown/unparseable versions
// (including the "dev" default) yield false so we never nag on a dev build.
func (u *UpdateChecker) UpdateAvailable(current string) (bool, string) {
	latest := u.Latest()
	if latest == "" {
		return false, ""
	}
	return semverLess(current, latest), latest
}

// semverLess reports whether version a is older than b. Both may have a leading
// "v"; each is compared field by field numerically (1.2.0 < 1.10.0). Non-numeric
// or empty versions (e.g. "dev") compare as "not older" so they never trigger a
// nag.
func semverLess(a, b string) bool {
	pa, oka := parseVer(a)
	pb, okb := parseVer(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

// parseVer parses "v1.2.3" / "1.2" into a 3-int array. Missing fields are 0.
// Returns ok=false if the first field isn't numeric (e.g. "dev", "v1.2.0-local").
func parseVer(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if s == "" {
		return out, false
	}
	parts := strings.SplitN(s, ".", 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		// Trim any pre-release/build suffix on the last field (e.g. "0-local").
		f := parts[i]
		for j := 0; j < len(f); j++ {
			if f[j] < '0' || f[j] > '9' {
				f = f[:j]
				break
			}
		}
		if f == "" {
			if i == 0 {
				return out, false
			}
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

