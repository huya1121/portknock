package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

// Firewall wraps ufw. All portknock-managed rules carry a comment of the form
// "portknock:<kind>:<key>" so ReconcileAll can find and purge them, keeping ufw
// state a pure function of our JSON state.
//
// Access model (two independent rule families):
//   - IP grants (kind "dyn"/"fixed"): `ufw allow from <ip>` — the IP may reach
//     ALL ports on the host.
//   - Open ports (kind "port"): `ufw allow <port>/tcp` — the port is reachable
//     from ANY source.
type Firewall struct {
	dryRun bool
	mu     sync.Mutex // serializes ufw invocations (ufw/iptables hold a global lock)
}

func NewFirewall(dryRun bool) *Firewall { return &Firewall{dryRun: dryRun} }

const commentPrefix = "portknock:"

// run executes ufw with the given args (never through a shell). Caller must
// hold f.mu: ufw/iptables take a single global lock and abort when invoked
// concurrently, so all ufw calls are serialized by the public methods that
// acquire f.mu before delegating to the *Locked helpers. (run itself must NOT
// lock — it is reached only from code already holding the lock, and sync.Mutex
// is not reentrant.)
func (f *Firewall) run(args ...string) (string, error) {
	if f.dryRun {
		log.Printf("[dry-run] ufw %s", strings.Join(args, " "))
		return "", nil
	}
	cmd := exec.Command("ufw", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("ufw %s: %w: %s", strings.Join(args, " "), err, out.String())
	}
	return out.String(), nil
}

// --- Lock-free internal helpers (caller must hold f.mu) ---

// allowIPLocked grants an IP access to all ports.
func (f *Firewall) allowIPLocked(ip, kind string) error {
	comment := commentPrefix + kind + ":" + ip
	_, err := f.run("allow", "from", ip, "comment", comment)
	return err
}

// deleteIPLocked removes an IP's all-ports grant (idempotent).
func (f *Firewall) deleteIPLocked(ip string) error {
	out, err := f.run("delete", "allow", "from", ip)
	if err != nil && !strings.Contains(strings.ToLower(out), "could not delete") {
		return err
	}
	return nil
}

// allowPortLocked opens a TCP port to any source.
func (f *Firewall) allowPortLocked(port int) error {
	comment := commentPrefix + "port:" + fmt.Sprint(port)
	_, err := f.run("allow", fmt.Sprintf("%d/tcp", port), "comment", comment)
	return err
}

// deletePortLocked closes a previously-opened TCP port (idempotent).
func (f *Firewall) deletePortLocked(port int) error {
	out, err := f.run("delete", "allow", fmt.Sprintf("%d/tcp", port))
	if err != nil && !strings.Contains(strings.ToLower(out), "could not delete") {
		return err
	}
	return nil
}

// --- Public operations (each takes f.mu once) ---

// AllowIP grants an IP all-port access.
func (f *Firewall) AllowIP(ip, kind string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allowIPLocked(ip, kind)
}

// AllowPort opens a TCP port to any source.
func (f *Firewall) AllowPort(port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allowPortLocked(port)
}

// RevokeIP removes a single IP's grant.
func (f *Firewall) RevokeIP(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleteIPLocked(ip)
}

// ReconcileAll makes ufw match the given state exactly. It holds the ufw lock
// for the whole operation and applies changes "add-before-delete": rules that
// should still exist are never removed, so a currently-whitelisted IP keeps
// access throughout — only genuinely-removed rules are deleted. Invalid
// IPs/ports are skipped with a warning.
func (f *Firewall) ReconcileAll(st State) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	desired := desiredRuleLabels(st) // key -> human label
	existing, err := f.listManagedRulesLocked()
	if err != nil {
		return err
	}
	existingKeys := map[string]managedRule{}
	for _, r := range existing {
		existingKeys[r.key()] = r
	}

	// 1. Add desired rules that are not already present.
	for key := range desired {
		if _, ok := existingKeys[key]; ok {
			continue
		}
		if err := f.addByKeyLocked(key); err != nil {
			log.Printf("reconcile: add %s: %v", key, err)
		}
	}
	// 2. Delete existing rules that are no longer desired.
	for key, r := range existingKeys {
		if _, ok := desired[key]; ok {
			continue
		}
		if r.kind == "port" {
			if err := f.deletePortLocked(r.port); err != nil {
				log.Printf("reconcile: delete port %d: %v", r.port, err)
			}
		} else {
			if err := f.deleteIPLocked(r.ip); err != nil {
				log.Printf("reconcile: delete ip %s: %v", r.ip, err)
			}
		}
	}
	return nil
}

// Preview computes, without executing, what ReconcileAll(st) would change
// against the live firewall. It returns the current managed rules and the rules
// that would be added / deleted, all as human-readable labels. Used by the
// admin UI to show a confirmation diff before applying.
func (f *Firewall) Preview(st State) (current, toAdd, toDelete []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	desired := desiredRuleLabels(st)
	existing, err := f.listManagedRulesLocked()
	if err != nil {
		return nil, nil, nil, err
	}
	existingKeys := map[string]managedRule{}
	for _, r := range existing {
		existingKeys[r.key()] = r
		current = append(current, r.label())
	}
	for key, label := range desired {
		if _, ok := existingKeys[key]; !ok {
			toAdd = append(toAdd, label)
		}
	}
	for key, r := range existingKeys {
		if _, ok := desired[key]; !ok {
			toDelete = append(toDelete, r.label())
		}
	}
	sort.Strings(current)
	sort.Strings(toAdd)
	sort.Strings(toDelete)
	return current, toAdd, toDelete, nil
}

// desiredRuleLabels returns, for a prospective state, the set of rules portknock
// would manage: a map of comment-key -> human-readable label. Invalid entries
// are skipped (mirrors ReconcileAll's validation).
func desiredRuleLabels(st State) map[string]string {
	m := map[string]string{}
	for _, p := range st.Ports {
		if p < 1 || p > 65535 {
			continue
		}
		m[commentPrefix+"port:"+fmt.Sprint(p)] = fmt.Sprintf("端口 %d/tcp（对所有人开放）", p)
	}
	for _, ip := range st.FixedIPs {
		if net.ParseIP(ip) == nil {
			continue
		}
		m[commentPrefix+"fixed:"+ip] = fmt.Sprintf("IP %s（固定·全端口）", ip)
	}
	for _, d := range st.Dynamic {
		if net.ParseIP(d.IP) == nil {
			continue
		}
		m[commentPrefix+"dyn:"+d.IP] = fmt.Sprintf("IP %s（动态·全端口）", d.IP)
	}
	return m
}

// addByKeyLocked installs the rule identified by a comment key (as produced by
// desiredRuleLabels / managedRule.key). Caller must hold f.mu.
func (f *Firewall) addByKeyLocked(key string) error {
	rest := strings.TrimPrefix(key, commentPrefix)
	kind, value, ok := strings.Cut(rest, ":")
	if !ok {
		return fmt.Errorf("bad rule key %q", key)
	}
	switch kind {
	case "port":
		var p int
		if _, err := fmt.Sscanf(value, "%d", &p); err != nil {
			return fmt.Errorf("bad port in key %q", key)
		}
		return f.allowPortLocked(p)
	case "fixed", "dyn":
		return f.allowIPLocked(value, kind)
	default:
		return fmt.Errorf("unknown rule kind %q", kind)
	}
}

type managedRule struct {
	kind string // "dyn", "fixed", or "port"
	ip   string // set for dyn/fixed
	port int    // set for port
}

// key returns the comment-tag key identifying this rule (matches desiredRuleLabels).
func (r managedRule) key() string {
	if r.kind == "port" {
		return commentPrefix + "port:" + fmt.Sprint(r.port)
	}
	return commentPrefix + r.kind + ":" + r.ip
}

// label returns a human-readable description of this rule for the UI.
func (r managedRule) label() string {
	switch r.kind {
	case "port":
		return fmt.Sprintf("端口 %d/tcp（对所有人开放）", r.port)
	case "fixed":
		return fmt.Sprintf("IP %s（固定·全端口）", r.ip)
	default:
		return fmt.Sprintf("IP %s（动态·全端口）", r.ip)
	}
}

// listManagedRulesLocked parses `ufw status` for rules tagged with our comment
// prefix. Caller must hold f.mu.
func (f *Firewall) listManagedRulesLocked() ([]managedRule, error) {
	if f.dryRun {
		return nil, nil
	}
	out, err := f.run("status")
	if err != nil {
		return nil, err
	}
	return parseManagedRules(out), nil
}

// parseManagedRules extracts managed rules from `ufw status` output. Lines carry
// a comment "portknock:<kind>:<key>". Split out for testability.
//
//	Anywhere         ALLOW   1.2.3.4        # portknock:dyn:1.2.3.4
//	80/tcp           ALLOW   Anywhere       # portknock:port:80
func parseManagedRules(status string) []managedRule {
	var rules []managedRule
	sc := bufio.NewScanner(strings.NewReader(status))
	for sc.Scan() {
		line := sc.Text()
		idx := strings.Index(line, "# "+commentPrefix)
		if idx < 0 {
			continue
		}
		comment := strings.TrimSpace(line[idx+2:]) // after "# "
		parts := strings.SplitN(comment, ":", 3)
		if len(parts) != 3 {
			continue
		}
		kind, key := parts[1], parts[2]
		switch kind {
		case "port":
			var port int
			if _, err := fmt.Sscanf(key, "%d", &port); err != nil {
				continue
			}
			rules = append(rules, managedRule{kind: "port", port: port})
		case "dyn", "fixed":
			rules = append(rules, managedRule{kind: kind, ip: key})
		}
	}
	return rules
}

