package main

import (
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name       string
		trustProxy bool
		remote     string
		xff        string
		want       string
	}{
		{"direct", false, "1.2.3.4:5000", "", "1.2.3.4"},
		{"xff ignored without trust", false, "1.2.3.4:5000", "9.9.9.9", "1.2.3.4"},
		{"xff honored with trust", true, "10.0.0.1:5000", "203.0.113.7", "203.0.113.7"},
		{"xff last hop", true, "10.0.0.1:5000", "9.9.9.9, 203.0.113.7", "203.0.113.7"},
		{"xff invalid falls back", true, "10.0.0.1:5000", "not-an-ip", "10.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{cfg: Config{TrustProxy: c.trustProxy}}
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := s.clientIP(r); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"22, 80, 443", []int{22, 80, 443}},
		{"22 80\n443", []int{22, 80, 443}},
		{"22;80", []int{22, 80}},
		{"", nil},
		{"abc, 80, x", []int{80}},
	}
	for _, c := range cases {
		if got := parsePorts(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parsePorts(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCanonicalIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{"  1.2.3.4  ", "1.2.3.4"},
		{"2001:0db8::1", "2001:db8::1"}, // non-canonical IPv6 normalized
		{"2001:db8::1", "2001:db8::1"},
		{"not-an-ip", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := canonicalIP(c.in); got != c.want {
			t.Errorf("canonicalIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProspectiveState(t *testing.T) {
	cur := State{
		Ports:    []int{80},
		FixedIPs: []string{"203.0.113.5"},
		Dynamic:  []Dynamic{{IP: "1.2.3.4"}, {IP: "5.6.7.8"}},
	}

	// ports replace
	next, err := prospectiveState(cur, "ports", "443, 80, 80, 70000")
	if err != nil || !reflect.DeepEqual(next.Ports, []int{80, 443}) {
		t.Errorf("ports: got %v err %v", next.Ports, err)
	}

	// fixed-add canonicalizes and dedups
	next, _ = prospectiveState(cur, "fixed-add", "2001:0db8::1")
	if !reflect.DeepEqual(next.FixedIPs, []string{"2001:db8::1", "203.0.113.5"}) {
		t.Errorf("fixed-add: got %v", next.FixedIPs)
	}

	// fixed-remove
	next, _ = prospectiveState(cur, "fixed-remove", "203.0.113.5")
	if len(next.FixedIPs) != 0 {
		t.Errorf("fixed-remove: got %v", next.FixedIPs)
	}

	// revoke drops one dynamic
	next, _ = prospectiveState(cur, "revoke", "1.2.3.4")
	if len(next.Dynamic) != 1 || next.Dynamic[0].IP != "5.6.7.8" {
		t.Errorf("revoke: got %v", next.Dynamic)
	}

	// invalid inputs
	if _, err := prospectiveState(cur, "fixed-add", "nope"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if _, err := prospectiveState(cur, "bogus", ""); err == nil {
		t.Error("expected error for unknown action")
	}

	// original must be unchanged (no aliasing)
	if len(cur.FixedIPs) != 1 || len(cur.Dynamic) != 2 || len(cur.Ports) != 1 {
		t.Error("prospectiveState mutated the input state")
	}
}

func TestHumanizeDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "刚刚"},
		{12 * time.Minute, "12分钟"},
		{90 * time.Minute, "1小时30分"},
		{3 * time.Hour, "3小时"},
		{(49 * time.Hour), "2天1小时"},
		{48 * time.Hour, "2天"},
	}
	for _, c := range cases {
		if got := humanizeDuration(c.d); got != c.want {
			t.Errorf("humanizeDuration(%s) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestCheckAPIKey(t *testing.T) {
	s := &Server{cfg: Config{APIKey: "secret-token"}}
	cases := []struct {
		header string
		want   bool
	}{
		{"Bearer secret-token", true},
		{"secret-token", true}, // tolerate missing prefix
		{"Bearer wrong", false},
		{"", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/api/grant", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		if got := s.checkAPIKey(r); got != c.want {
			t.Errorf("checkAPIKey(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}
