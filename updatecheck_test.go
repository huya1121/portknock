package main

import "testing"

func TestSemverLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v1.1.8", "v1.1.9", true},    // patch bump
		{"v1.1.9", "v1.2.0", true},    // minor bump
		{"v1.2.0", "v1.10.0", true},   // numeric, not lexical (2 < 10)
		{"1.2.0", "1.2.0", false},     // equal
		{"v1.2.1", "v1.2.0", false},   // newer local
		{"v1.2", "v1.2.0", false},     // missing patch == 0
		{"dev", "v1.2.0", false},      // dev never nags
		{"v1.2.0", "dev", false},      // unparseable remote
		{"v1.2.0-local", "v1.3.0", true}, // suffix trimmed, 2<3
		{"", "v1.0.0", false},         // empty
	}
	for _, c := range cases {
		if got := semverLess(c.a, c.b); got != c.want {
			t.Errorf("semverLess(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestUpdateAvailable(t *testing.T) {
	u := NewUpdateChecker()
	// Nothing fetched yet.
	if ok, _ := u.UpdateAvailable("v1.1.8"); ok {
		t.Error("no latest cached -> should not report available")
	}
	u.mu.Lock()
	u.latest = "v1.2.0"
	u.mu.Unlock()
	if ok, latest := u.UpdateAvailable("v1.1.8"); !ok || latest != "v1.2.0" {
		t.Errorf("expected update available to v1.2.0, got ok=%v latest=%q", ok, latest)
	}
	if ok, _ := u.UpdateAvailable("v1.2.0"); ok {
		t.Error("same version -> should not report available")
	}
	if ok, _ := u.UpdateAvailable("dev"); ok {
		t.Error("dev build -> should not nag")
	}
}

