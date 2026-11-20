package main

import "testing"

func TestActiveIPs(t *testing.T) {
	// Dynamic IPs have all-port access, so any connection counts as activity
	// regardless of destination port.
	conntrack := `ipv4 2 tcp 6 431999 ESTABLISHED src=1.2.3.4 dst=10.0.0.1 sport=5000 dport=80 src=10.0.0.1 dst=1.2.3.4 sport=80 dport=5000 [ASSURED] mark=0 use=1
ipv4 2 udp 17 29 src=9.9.9.9 dst=10.0.0.1 sport=1 dport=53 src=10.0.0.1 dst=9.9.9.9 sport=53 dport=1 mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=4.4.4.4 dst=10.0.0.1 sport=5200 dport=8080 src=10.0.0.1 dst=4.4.4.4 sport=8080 dport=5200 [ASSURED] mark=0 use=1`

	dyn := map[string]bool{"1.2.3.4": true, "9.9.9.9": true}

	active := activeIPs(conntrack, dyn)

	if !active["1.2.3.4"] {
		t.Errorf("expected 1.2.3.4 active (tcp dport 80)")
	}
	if !active["9.9.9.9"] {
		t.Errorf("expected 9.9.9.9 active (any connection counts now, incl. udp)")
	}
	if active["4.4.4.4"] {
		t.Errorf("4.4.4.4 not a dynamic IP, should be ignored")
	}
	if len(active) != 2 {
		t.Errorf("expected 2 active IPs, got %d: %v", len(active), active)
	}
}

// TestActiveIPsIPv6 verifies that conntrack's zero-padded/expanded IPv6 form
// matches a dynamic IP stored in Go's canonical (compressed) form.
func TestActiveIPsIPv6(t *testing.T) {
	// conntrack writes the expanded form; our store holds the canonical form.
	conntrack := `ipv6 10 tcp 6 19 TIME_WAIT src=240b:4009:0254:d800:b19a:e569:41fa:5850 dst=2409:8c4c:0e00:0210:8000:0000:0b00:0087 sport=51980 dport=80 [ASSURED] mark=0 use=2`
	dyn := map[string]bool{"240b:4009:254:d800:b19a:e569:41fa:5850": true} // canonical

	active := activeIPs(conntrack, dyn)

	// Result is keyed by canonical form.
	if !active["240b:4009:254:d800:b19a:e569:41fa:5850"] {
		t.Errorf("expected expanded IPv6 to match canonical dynamic IP; got %v", active)
	}
}

func TestFirstValue(t *testing.T) {
	line := "foo src=1.2.3.4 dport=80 bar"
	if got := firstValue(line, "src="); got != "1.2.3.4" {
		t.Errorf("src: got %q", got)
	}
	if got := firstValue(line, "dport="); got != "80" {
		t.Errorf("dport: got %q", got)
	}
	if got := firstValue(line, "missing="); got != "" {
		t.Errorf("missing: got %q", got)
	}
	// value at end of line (no trailing space)
	if got := firstValue("x=end", "x="); got != "end" {
		t.Errorf("end: got %q", got)
	}
}

