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

// Auth manages the single admin password and in-memory session tokens, plus a
// per-session CSRF token.
type Auth struct {
	password string
	mu       sync.Mutex
	sessions map[string]session // token -> session
	ttl      time.Duration
}

type session struct {
	csrf    string
	expires time.Time
}

func NewAuth(password string, ttl time.Duration) *Auth {
	return &Auth{password: password, sessions: map[string]session{}, ttl: ttl}
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

