package main

import "testing"

func TestParseManagedRules(t *testing.T) {
	status := `Status: active

To                         Action      From
--                         ------      ----
Anywhere                   ALLOW       1.2.3.4                    # portknock:dyn:1.2.3.4
Anywhere                   ALLOW       203.0.113.5                # portknock:fixed:203.0.113.5
80/tcp                     ALLOW       Anywhere                   # portknock:port:80
443/tcp                    ALLOW       Anywhere                   # portknock:port:443
22/tcp                     ALLOW       Anywhere                   # some other comment
`
	rules := parseManagedRules(status)
	if len(rules) != 4 {
		t.Fatalf("expected 4 managed rules, got %d: %+v", len(rules), rules)
	}

	var dyn, fixed, ports int
	for _, r := range rules {
		switch r.kind {
		case "dyn":
			dyn++
			if r.ip != "1.2.3.4" {
				t.Errorf("dyn ip: %q", r.ip)
			}
		case "fixed":
			fixed++
			if r.ip != "203.0.113.5" {
				t.Errorf("fixed ip: %q", r.ip)
			}
		case "port":
			ports++
			if r.port != 80 && r.port != 443 {
				t.Errorf("unexpected port: %d", r.port)
			}
		}
	}
	if dyn != 1 || fixed != 1 || ports != 2 {
		t.Errorf("counts dyn=%d fixed=%d ports=%d", dyn, fixed, ports)
	}
}

func TestParseManagedRulesIPv6Comment(t *testing.T) {
	// The full IPv6 address survives via SplitN(...,3) on the comment.
	status := `Anywhere (v6)              ALLOW       2001:db8::1                # portknock:fixed:2001:db8::1`
	rules := parseManagedRules(status)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].kind != "fixed" || rules[0].ip != "2001:db8::1" {
		t.Errorf("ipv6 rule not preserved: %+v", rules[0])
	}
}

func TestDryRunNoExec(t *testing.T) {
	fw := NewFirewall(true)
	if err := fw.AllowIP("1.2.3.4", "dyn"); err != nil {
		t.Errorf("dry-run AllowIP should not error: %v", err)
	}
	if err := fw.AllowPort(80); err != nil {
		t.Errorf("dry-run AllowPort should not error: %v", err)
	}
	if err := fw.RevokeIP("1.2.3.4"); err != nil {
		t.Errorf("dry-run RevokeIP should not error: %v", err)
	}
	st := State{Ports: []int{80, 443}, FixedIPs: []string{"203.0.113.5"}, Dynamic: []Dynamic{{IP: "1.2.3.4"}}}
	if err := fw.ReconcileAll(st); err != nil {
		t.Errorf("dry-run reconcile should not error: %v", err)
	}
}

func TestDesiredRuleLabels(t *testing.T) {
	st := State{Ports: []int{80, 70000}, FixedIPs: []string{"203.0.113.5", "bad"}, Dynamic: []Dynamic{{IP: "1.2.3.4"}}}
	m := desiredRuleLabels(st)
	// 70000 (invalid port) and "bad" (invalid ip) are skipped.
	if len(m) != 3 {
		t.Fatalf("expected 3 valid rules, got %d: %v", len(m), m)
	}
	for _, key := range []string{"portknock:port:80", "portknock:fixed:203.0.113.5", "portknock:dyn:1.2.3.4"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
}

func TestPreviewDryRun(t *testing.T) {
	// In dry-run, listManagedRules returns nothing, so everything desired is "add".
	fw := NewFirewall(true)
	st := State{Ports: []int{80}, FixedIPs: []string{"203.0.113.5"}}
	current, add, del, err := fw.Preview(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(current) != 0 {
		t.Errorf("expected no current rules in dry-run, got %v", current)
	}
	if len(add) != 2 {
		t.Errorf("expected 2 adds, got %v", add)
	}
	if len(del) != 0 {
		t.Errorf("expected 0 deletes, got %v", del)
	}
}

