package main

import (
	"testing"
	"time"
)

func TestAuthLockout(t *testing.T) {
	a := NewAuth("secret", time.Hour)
	ip := "1.2.3.4"

	// maxFails consecutive failures -> locked.
	for i := 0; i < maxFails; i++ {
		a.RecordFail(ip)
	}
	locked, left := a.Locked(ip)
	if !locked || left <= 0 {
		t.Fatalf("expected lockout after %d fails, got locked=%v left=%v", maxFails, locked, left)
	}
}

func TestAuthWindowDecay(t *testing.T) {
	a := NewAuth("secret", time.Hour)
	ip := "1.2.3.4"

	// maxFails-1 failures, then simulate the window elapsing by backdating `first`.
	for i := 0; i < maxFails-1; i++ {
		a.RecordFail(ip)
	}
	a.mu.Lock()
	f := a.fails[ip]
	f.first = time.Now().Add(-failWindow - time.Minute) // older than the window
	a.fails[ip] = f
	a.mu.Unlock()

	// The next failure should start a fresh window, NOT trip the lock.
	a.RecordFail(ip)
	if locked, _ := a.Locked(ip); locked {
		t.Error("failures older than the window should decay, not accumulate to a lockout")
	}
}

func TestAuthSuccessClears(t *testing.T) {
	a := NewAuth("secret", time.Hour)
	ip := "1.2.3.4"
	a.RecordFail(ip)
	a.RecordFail(ip)
	a.RecordSuccess(ip)
	a.mu.Lock()
	_, present := a.fails[ip]
	a.mu.Unlock()
	if present {
		t.Error("RecordSuccess should clear the IP's fail state")
	}
}

func TestAuthSweepUnboundedGrowth(t *testing.T) {
	a := NewAuth("secret", time.Hour)
	// One failure each from many IPs; without a sweep these would accumulate.
	for i := 0; i < 50; i++ {
		a.RecordFail(netIP(i))
	}
	// Backdate every entry past the window, then one more RecordFail triggers a sweep.
	a.mu.Lock()
	for ip, f := range a.fails {
		f.first = time.Now().Add(-failWindow - time.Minute)
		a.fails[ip] = f
	}
	a.mu.Unlock()
	a.RecordFail("254.254.254.254")

	a.mu.Lock()
	n := len(a.fails)
	a.mu.Unlock()
	// Only the just-added entry (in an active window) should remain.
	if n != 1 {
		t.Errorf("expected stale fail entries swept, got %d remaining", n)
	}
}

func netIP(i int) string {
	return "10.0.0." + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
