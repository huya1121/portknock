package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const sessionCookie = "portknock_session"

// Brute-force limits: after maxFails failed logins from one IP within failWindow,
// that IP is locked out for lockDuration. Failures older than failWindow decay
// (the counter restarts), so a legitimate admin who mistypes occasionally over a
// long span is never locked out.
const (
	maxFails     = 5
	lockDuration = 5 * time.Minute
	failWindow   = 15 * time.Minute
)

// Auth manages the single admin password and in-memory session tokens, plus a
// per-session CSRF token and per-IP login throttling.
type Auth struct {
	password string
	mu       sync.Mutex
	sessions map[string]session  // token -> session
	fails    map[string]failInfo // client IP -> recent failures
	ttl      time.Duration
}

type session struct {
	csrf    string
	expires time.Time
}

type failInfo struct {
	count  int
	first  time.Time // when the current counting window started
	locked time.Time // time until which the IP is locked (zero = not locked)
}

func NewAuth(password string, ttl time.Duration) *Auth {
	return &Auth{
		password: password,
		sessions: map[string]session{},
		fails:    map[string]failInfo{},
		ttl:      ttl,
	}
}

// Locked reports whether ip is currently locked out, and if so for how long.
func (a *Auth) Locked(ip string) (bool, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	if f.locked.IsZero() || time.Now().After(f.locked) {
		return false, 0
	}
	return true, time.Until(f.locked).Round(time.Second)
}

// RecordFail notes a failed login from ip and locks it once maxFails is reached
// within failWindow. Failures older than failWindow decay (counter restarts).
func (a *Auth) RecordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	a.sweepFailsLocked(now)
	f := a.fails[ip]
	// Start a fresh window if this is the first failure or the previous window
	// has elapsed.
	if f.count == 0 || now.Sub(f.first) > failWindow {
		f.first = now
		f.count = 0
	}
	f.count++
	if f.count >= maxFails {
		f.locked = now.Add(lockDuration)
		f.count = 0 // reset counter; the lock itself now gates access
	}
	a.fails[ip] = f
}

// sweepFailsLocked drops fail entries that are neither locked nor within an
// active counting window, so the map can't grow unbounded under IP rotation.
// Caller must hold a.mu.
func (a *Auth) sweepFailsLocked(now time.Time) {
	for ip, f := range a.fails {
		lockedActive := !f.locked.IsZero() && now.Before(f.locked)
		windowActive := f.count > 0 && now.Sub(f.first) <= failWindow
		if !lockedActive && !windowActive {
			delete(a.fails, ip)
		}
	}
}

// RecordSuccess clears any failure state for ip after a good login.
func (a *Auth) RecordSuccess(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, ip)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CheckPassword compares pw to the admin password in constant time.
func (a *Auth) CheckPassword(pw string) bool {
	return subtle.ConstantTimeCompare([]byte(pw), []byte(a.password)) == 1
}

// NewSession creates a session and returns (sessionToken, csrfToken). It also
// sweeps expired sessions so abandoned entries (never looked up again) cannot
// accumulate unboundedly.
func (a *Auth) NewSession() (string, string) {
	token := randomToken()
	csrf := randomToken()
	now := time.Now()
	a.mu.Lock()
	for k, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, k)
		}
	}
	a.sessions[token] = session{csrf: csrf, expires: now.Add(a.ttl)}
	a.mu.Unlock()
	return token, csrf
}

// lookup returns the session for a request and whether it is valid.
func (a *Auth) lookup(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok {
		return session{}, false
	}
	if time.Now().After(s.expires) {
		delete(a.sessions, c.Value)
		return session{}, false
	}
	return s, true
}

// Authenticated reports whether the request carries a valid session.
func (a *Auth) Authenticated(r *http.Request) bool {
	_, ok := a.lookup(r)
	return ok
}

// CSRF returns the CSRF token for the request's session, or "".
func (a *Auth) CSRF(r *http.Request) string {
	s, ok := a.lookup(r)
	if !ok {
		return ""
	}
	return s.csrf
}

// CheckCSRF verifies the posted token matches the session's CSRF token.
func (a *Auth) CheckCSRF(r *http.Request, token string) bool {
	s, ok := a.lookup(r)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.csrf)) == 1
}

// Logout invalidates the request's session.
func (a *Auth) Logout(r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return
	}
	a.mu.Lock()
	delete(a.sessions, c.Value)
	a.mu.Unlock()
}
