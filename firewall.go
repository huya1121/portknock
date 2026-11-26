package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
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
//   - Open ports (kind "port"): `ufw allow <port>` — the port is reachable from
//     ANY source, on BOTH TCP and UDP (bare port = both protocols in ufw).
type Firewall struct {
	dryRun bool
	bin    string     // resolved absolute path to the ufw binary
	mu     sync.Mutex // serializes ufw invocations (ufw/iptables hold a global lock)
}

func NewFirewall(dryRun bool) *Firewall {
	return &Firewall{dryRun: dryRun, bin: resolveUFW()}
}

// resolveUFW locates the ufw binary. It prefers $PATH, then falls back to the
// usual absolute locations, because systemd units often run with a minimal PATH
// that excludes /usr/sbin where ufw lives. Returns "ufw" if nothing is found so
// the error message is still meaningful.
func resolveUFW() string {
	if p, err := exec.LookPath("ufw"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw", "/bin/ufw", "/usr/local/sbin/ufw"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return "ufw"
}

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
	cmd := exec.Command(f.bin, args...)
	// Force a C locale so ufw's output (parsed in listManagedRulesLocked and
	// matched in deleteIPLocked/deletePortLocked) is always English, regardless
	// of the host's LANG. Otherwise "Status: active" / "Could not delete" checks
	// break on localized hosts.
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
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

// allowIPLocked grants an IP access to all ports. The comment is keyed by IP
// alone ("portknock:ip:<ip>"): ufw keeps only one `allow from <ip>` rule
// regardless of comment, so fixed and dynamic grants for the same IP must not
// use distinct comments (that caused reconcile churn and erroneous deletes).
func (f *Firewall) allowIPLocked(ip string) error {
	comment := ipRuleKey(ip)
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

// allowPortLocked opens a port to any source for BOTH TCP and UDP. Passing the
// bare port number (no "/tcp") makes ufw add both protocols in one rule.
func (f *Firewall) allowPortLocked(port int) error {
	comment := commentPrefix + "port:" + fmt.Sprint(port)
	_, err := f.run("allow", fmt.Sprint(port), "comment", comment)
	return err
}

// deletePortLocked closes a previously-opened port (idempotent). proto is "" for
// a both-protocols rule, or "tcp"/"udp" to delete a proto-specific rule (e.g. a
// tcp-only rule left by an older binary, during migration). The spec must match
// how the rule was added or ufw won't find it.
func (f *Firewall) deletePortLocked(port int, proto string) error {
	spec := fmt.Sprint(port)
	if proto != "" {
		spec = fmt.Sprintf("%d/%s", port, proto)
	}
	out, err := f.run("delete", "allow", spec)
	if err != nil && !strings.Contains(strings.ToLower(out), "could not delete") {
		return err
	}
	return nil
}

// --- Public operations (each takes f.mu once) ---

// AllowIP grants an IP all-port access.
func (f *Firewall) AllowIP(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allowIPLocked(ip)
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

// Disable turns the whole firewall off (`ufw disable`) — an emergency escape so
// an admin locked out by a misconfiguration can restore full access from the
// panel. All ports become reachable until Enable is called.
func (f *Firewall) Disable() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.run("disable")
	return err
}

// Enable turns the firewall back on (`ufw --force enable`) and re-applies the
// current state. --force avoids the interactive "may disrupt SSH" prompt.
func (f *Firewall) Enable(st State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.run("--force", "enable"); err != nil {
		return err
	}
	return f.reconcileLocked(st)
}

// IsActive reports whether ufw is currently enabled.
func (f *Firewall) IsActive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dryRun {
		return true
	}
	out, err := f.run("status")
	if err != nil {
		return false
	}
	return strings.Contains(out, "Status: active")
}

// defaultUFWFile is where ufw keeps the IPV6=yes/no toggle.
const defaultUFWFile = "/etc/default/ufw"

// ipv6AllowAllComment tags the "allow all inbound IPv6" rule that implements the
// "IPv6 放开(全通)" mode. Its presence means IPv6 is unmanaged (全通); its
// absence means IPv6 follows the same whitelist as IPv4.
const ipv6AllowAllComment = "portknock:ipv6-allow-all"

// IPv6Managed reports whether IPv6 follows the whitelist (true) or is fully open
// (false). "Fully open" is implemented by an install-managed `allow to ::/0`
// rule — NOT by IPV6=no (which merely makes ufw ignore IPv6 and, on many
// systems, breaks IPv6 entirely because NDP/RA stop being permitted). IPV6 is
// always kept =yes so the stack works and ufw's before6.rules permits ICMPv6.
func (f *Firewall) IPv6Managed() bool {
	if f.dryRun {
		return true
	}
	out, err := f.run("status")
	if err != nil {
		return true // assume managed if we can't tell
	}
	// Managed unless the allow-all IPv6 rule is present.
	return !strings.Contains(out, ipv6AllowAllComment)
}

// SetIPv6Managed switches how IPv6 inbound traffic is treated.
//   - managed=true  → IPv6 follows the same whitelist as IPv4 (remove allow-all).
//   - managed=false → IPv6 fully open: a single `allow to ::/0` rule permits ALL
//     inbound IPv6 while IPv4 keeps its whitelist.
//
// Either way ufw KEEPS managing IPv6 (IPV6=yes) so the IPv6 stack works and
// ufw's before6.rules permits the essential ICMPv6/NDP — this is the fix for
// "enabling ufw killed IPv6": the old behaviour set IPV6=no, which broke address
// configuration instead of opening IPv6.
func (f *Firewall) SetIPv6Managed(managed bool, st State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dryRun {
		if managed {
			log.Printf("[dry-run] ufw delete allow to ::/0 (IPv6 -> whitelist)")
		} else {
			log.Printf("[dry-run] ufw allow to ::/0 comment %s (IPv6 -> open)", ipv6AllowAllComment)
		}
		return nil
	}

	// Always ensure ufw manages IPv6; otherwise IPv6 breaks regardless of mode.
	if err := f.ensureIPv6Yes(); err != nil {
		log.Printf("ensure IPV6=yes: %v", err)
	}

	if managed {
		// Remove the allow-all rule (idempotent) -> IPv6 obeys the whitelist.
		out, err := f.run("delete", "allow", "to", "::/0")
		if err != nil && !strings.Contains(strings.ToLower(out), "could not delete") {
			return err
		}
	} else {
		// Add the allow-all rule -> every inbound IPv6 packet is accepted.
		if _, err := f.run("allow", "to", "::/0", "comment", ipv6AllowAllComment); err != nil {
			return err
		}
	}
	if _, err := f.run("reload"); err != nil {
		log.Printf("ufw reload after IPv6 change: %v (applies on enable)", err)
	}
	return f.reconcileLocked(st)
}

// ensureIPv6Yes forces IPV6=yes in /etc/default/ufw so ufw manages IPv6 (and its
// before6.rules permits NDP/RA). Caller holds f.mu.
func (f *Firewall) ensureIPv6Yes() error {
	data, err := os.ReadFile(defaultUFWFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", defaultUFWFile, err)
	}
	lines := strings.Split(string(data), "\n")
	changed, found := false, false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "IPV6=") {
			found = true
			if strings.TrimSpace(line) != "IPV6=yes" {
				lines[i] = "IPV6=yes"
				changed = true
			}
		}
	}
	if !found {
		lines = append(lines, "IPV6=yes")
		changed = true
	}
	if changed {
		if err := os.WriteFile(defaultUFWFile, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", defaultUFWFile, err)
		}
	}
	return nil
}

func boolYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ReconcileAll makes ufw match the given state exactly. It holds the ufw lock
// for the whole operation and applies changes "add-before-delete": rules that
// should still exist are never removed, so a currently-whitelisted IP keeps
// access throughout — only genuinely-removed rules are deleted. Invalid
// IPs/ports are skipped with a warning.
func (f *Firewall) ReconcileAll(st State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reconcileLocked(st)
}

// reconcileLocked is ReconcileAll's body. Caller must hold f.mu.
func (f *Firewall) reconcileLocked(st State) error {
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
			if err := f.deletePortLocked(r.port, r.proto); err != nil {
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

// allOpenPorts returns the deduped union of all open-port sources: local-only
// ports, ports this node distributes as a center, and ports received from an
// upstream center. On a child they all collapse to the same portknock:port:<p>
// ufw rule, so the firewall only needs the union — the categories matter only
// in the state layer.
func allOpenPorts(st State) []int {
	seen := map[int]bool{}
	var out []int
	for _, list := range [][]int{st.Ports, st.SyncPorts, st.ReceivedPorts} {
		for _, p := range list {
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// ipRuleKey is the reconcile key for an IP grant. It is keyed by IP ALONE (not
// by kind), because ufw collapses `allow from <ip>` to a single physical rule
// regardless of the comment — so fixed and dynamic grants for the same IP are
// one rule, and must map to one key, or reconcile would churn (re-add every
// pass) and, worse, delete the shared rule when only one of the two is dropped.
func ipRuleKey(ip string) string { return commentPrefix + "ip:" + ip }

// desiredRuleLabels returns, for a prospective state, the set of rules portknock
// would manage: a map of reconcile-key -> human-readable label. Invalid entries
// are skipped (mirrors ReconcileAll's validation). An IP that is both fixed and
// dynamic yields a single entry, labelled as fixed (the stronger, non-expiring
// grant), since there is only one underlying ufw rule.
func desiredRuleLabels(st State) map[string]string {
	m := map[string]string{}
	for _, p := range allOpenPorts(st) {
		if p < 1 || p > 65535 {
			continue
		}
		m[portRuleKey(p, "")] = fmt.Sprintf("端口 %d（TCP+UDP，对所有人开放）", p)
	}
	// Dynamic first, then fixed, so fixed's label wins on overlap.
	for _, d := range st.Dynamic {
		if net.ParseIP(d.IP) == nil {
			continue
		}
		m[ipRuleKey(d.IP)] = fmt.Sprintf("IP %s（动态·全端口）", d.IP)
	}
	for _, ip := range st.FixedIPs {
		if net.ParseIP(ip) == nil {
			continue
		}
		m[ipRuleKey(ip)] = fmt.Sprintf("IP %s（固定·全端口）", ip)
	}
	// Fixed IPs received from an upstream center behave exactly like local fixed.
	for _, ip := range st.ReceivedFixedIPs {
		if net.ParseIP(ip) == nil {
			continue
		}
		m[ipRuleKey(ip)] = fmt.Sprintf("IP %s（固定·全端口·来自上游）", ip)
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
	case "ip":
		return f.allowIPLocked(value)
	default:
		return fmt.Errorf("unknown rule kind %q", kind)
	}
}

type managedRule struct {
	kind  string // "ip" or "port"
	ip    string // set for ip
	port  int    // set for port
	proto string // port only: "" = both tcp+udp, or "tcp"/"udp" for a proto-specific rule
}

// key returns the reconcile key identifying this rule (matches desiredRuleLabels).
// IP grants key by IP alone so fixed/dyn comments on the same physical rule
// collapse to one key (see ipRuleKey). Port rules include the protocol so a
// legacy tcp-only rule (older binary) does NOT match the desired both-protocol
// rule — reconcile then deletes the tcp-only one and re-adds it for tcp+udp.
func (r managedRule) key() string {
	if r.kind == "port" {
		return portRuleKey(r.port, r.proto)
	}
	return ipRuleKey(r.ip)
}

// portRuleKey keys a port rule. proto "" (both tcp+udp) is the desired form.
func portRuleKey(port int, proto string) string {
	k := commentPrefix + "port:" + fmt.Sprint(port)
	if proto != "" {
		k += "/" + proto
	}
	return k
}

// label returns a human-readable description of this rule for the UI.
func (r managedRule) label() string {
	switch r.kind {
	case "port":
		if r.proto != "" {
			return fmt.Sprintf("端口 %d/%s（对所有人开放）", r.port, r.proto)
		}
		return fmt.Sprintf("端口 %d（TCP+UDP，对所有人开放）", r.port)
	default:
		return fmt.Sprintf("IP %s（全端口）", r.ip)
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
// a comment "portknock:<kind>:<key>". Split out for testability. For port rules
// the protocol is read from the "To" column (first field): "8000/tcp" / "8000/udp"
// are proto-specific; a bare "8000" means both tcp+udp. This lets reconcile tell
// a legacy tcp-only rule apart from the desired both-protocol rule and migrate it.
//
//	Anywhere         ALLOW   1.2.3.4        # portknock:ip:1.2.3.4
//	8000             ALLOW   Anywhere       # portknock:port:8000   (tcp+udp)
//	80/tcp           ALLOW   Anywhere       # portknock:port:80     (legacy tcp-only)
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
			// Determine protocol from the "To" column (first whitespace field),
			// e.g. "8000/tcp" -> "tcp", "8000" -> "" (both). (v6) suffix ignored.
			proto := ""
			if fields := strings.Fields(line); len(fields) > 0 {
				if _, p, ok := strings.Cut(fields[0], "/"); ok {
					proto = p
				}
			}
			rules = append(rules, managedRule{kind: "port", port: port, proto: proto})
		case "ip":
			rules = append(rules, managedRule{kind: "ip", ip: key})
		case "dyn", "fixed":
			// Legacy comment from an older binary (keyed by kind). Still a single
			// `allow from <ip>` rule — normalize to the IP-only kind so reconcile
			// matches it and migrates the comment to "ip:" on the next add.
			rules = append(rules, managedRule{kind: "ip", ip: key})
		}
	}
	return rules
}

