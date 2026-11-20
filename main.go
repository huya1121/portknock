package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

//go:embed web/*.html
var webFS embed.FS

var templates = template.Must(template.ParseFS(webFS, "web/*.html"))

// Config holds runtime configuration.
type Config struct {
	Listen     string
	StatePath  string
	AdminPass  string
	TrustProxy bool
	Poll       time.Duration
	Expiry     time.Duration
	DryRun     bool
	SecureCookie bool
	APIKey     string
}

// Server bundles the handlers' dependencies.
type Server struct {
	cfg   Config
	store *Store
	fw    *Firewall
	auth  *Auth
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Listen, "listen", ":8080", "HTTP listen address")
	flag.StringVar(&cfg.StatePath, "state", "/var/lib/portknock/state.json", "path to state file")
	flag.StringVar(&cfg.AdminPass, "admin-pass", "", "admin password (or env PORTKNOCK_ADMIN_PASS)")
	flag.BoolVar(&cfg.TrustProxy, "trust-proxy", false, "trust X-Forwarded-For (only behind a trusted reverse proxy)")
	flag.DurationVar(&cfg.Poll, "poll", 2*time.Minute, "conntrack poll interval")
	flag.DurationVar(&cfg.Expiry, "expiry", 48*time.Hour, "idle expiry window for dynamic IPs")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "log ufw commands instead of executing them")
	flag.BoolVar(&cfg.SecureCookie, "secure-cookie", false, "set Secure flag on cookies (enable only when served over HTTPS; required cookies are dropped by browsers on plain HTTP if set)")
	flag.StringVar(&cfg.APIKey, "api-key", "", "bearer token for the JSON API (or env PORTKNOCK_API_KEY); empty disables the API")
	flag.Parse()

	if cfg.AdminPass == "" {
		cfg.AdminPass = os.Getenv("PORTKNOCK_ADMIN_PASS")
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("PORTKNOCK_API_KEY")
	}
	if cfg.AdminPass == "" {
		log.Fatal("admin password required: set --admin-pass or PORTKNOCK_ADMIN_PASS")
	}

	store, err := NewStore(cfg.StatePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}
	fw := NewFirewall(cfg.DryRun)
	srv := &Server{
		cfg:   cfg,
		store: store,
		fw:    fw,
		auth:  NewAuth(cfg.AdminPass, 12*time.Hour),
	}

	// Reconcile firewall to match persisted state at startup.
	if err := fw.ReconcileAll(store.Snapshot()); err != nil {
		log.Printf("startup reconcile: %v", err)
	}

	// Start the janitor.
	janitor := NewJanitor(store, fw, cfg.Poll, cfg.Expiry)
	stop := make(chan struct{})
	go janitor.Run(stop)

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/grant", srv.handleGrant)
	mux.HandleFunc("/admin", srv.handleAdmin)
	mux.HandleFunc("/admin/login", srv.handleLogin)
	mux.HandleFunc("/admin/logout", srv.handleLogout)
	mux.HandleFunc("/admin/ports", srv.handlePorts)
	mux.HandleFunc("/admin/fixed", srv.handleFixed)
	mux.HandleFunc("/admin/revoke", srv.handleRevoke)
	mux.HandleFunc("/admin/preview", srv.handlePreview)
	mux.HandleFunc("/admin/firewall", srv.handleFirewall)
	mux.HandleFunc("/admin/ipv6", srv.handleIPv6Toggle)
	mux.HandleFunc("/api/grant", srv.handleAPIGrant)

	log.Printf("portknock %s listening on %s (dry-run=%v, expiry=%s, poll=%s, api=%v)", version, cfg.Listen, cfg.DryRun, cfg.Expiry, cfg.Poll, cfg.APIKey != "")
	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		log.Fatal(err)
	}
}

// canonicalIP normalizes an IP string to its canonical form (e.g.
// "2001:0db8::1" -> "2001:db8::1"), so the same host always compares and
// deduplicates identically. Returns "" if s is not a valid IP.
func canonicalIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// clientIP returns the best-effort client IP in canonical form. Honors the last
// X-Forwarded-For hop only when TrustProxy is set; otherwise uses the TCP peer
// address.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if c := canonicalIP(last); c != "" {
				return c
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if c := canonicalIP(host); c != "" {
		return c
	}
	return host
}

// --- User-facing handlers ---

type indexData struct {
	ClientIP string
	Ports    []int
	Granted  bool
	Error    string
	CSRF     string
}

const grantCSRFCookie = "portknock_grant_csrf"

// grantToken returns the double-submit CSRF token for the public /grant form,
// reading it from the request cookie or minting a new one and setting the
// cookie on w. Because the attacker's cross-site POST cannot read or set this
// host's cookie, it cannot supply a form value matching the victim's cookie.
func (s *Server) grantToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(grantCSRFCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok := randomToken()
	http.SetCookie(w, &http.Cookie{
		Name:     grantCSRFCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: http.SameSiteStrictMode,
	})
	return tok
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	st := s.store.Snapshot()
	data := indexData{
		ClientIP: s.clientIP(r),
		Ports:    st.Ports,
		Granted:  r.URL.Query().Get("granted") == "1",
		CSRF:     s.grantToken(w, r),
	}
	s.render(w, "index.html", data)
}

// grantDynamic records a dynamic (all-port) grant for ip and installs its ufw
// rule. ip must already be validated by the caller. If the firewall rule cannot
// be installed, the store grant is rolled back so the UI never shows an IP as
// granted while it has no actual access.
func (s *Server) grantDynamic(ip string) error {
	if err := s.store.Grant(ip, time.Now()); err != nil {
		return err
	}
	if err := s.fw.AllowIP(ip, "dyn"); err != nil {
		// Roll back so state stays consistent with the firewall.
		if rbErr := s.store.RevokeDynamic(ip); rbErr != nil {
			log.Printf("grant rollback %s: %v", ip, rbErr)
		}
		return fmt.Errorf("install firewall rule: %w", err)
	}
	log.Printf("granted dynamic all-port access to %s", ip)
	return nil
}

func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Double-submit CSRF: the form token must match the cookie. A cross-site
	// attacker can forge the POST but cannot read/set this host's cookie.
	cookie, err := r.Cookie(grantCSRFCookie)
	if err != nil || cookie.Value == "" ||
		subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(cookie.Value)) != 1 {
		http.Error(w, "invalid or missing CSRF token; reload the page and try again", http.StatusForbidden)
		return
	}
	ip := s.clientIP(r)
	if net.ParseIP(ip) == nil {
		http.Error(w, "could not determine a valid client IP", http.StatusBadRequest)
		return
	}
	if err := s.grantDynamic(ip); err != nil {
		log.Printf("grant %s: %v", ip, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/?granted=1", http.StatusSeeOther)
}

// handleAPIGrant is a JSON endpoint for programmatic whitelisting.
//
//	POST /api/grant            Authorization: Bearer <api-key>
//	{"ip": "203.0.113.9"}      // optional; defaults to the caller's IP
//
// Responds 200 {"ip":"...","status":"granted"}.
func (s *Server) handleAPIGrant(w http.ResponseWriter, r *http.Request) {
	if s.cfg.APIKey == "" {
		http.Error(w, "api disabled", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.checkAPIKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	// Body is optional; {"ip":"..."} overrides the detected caller IP.
	var body struct {
		IP string `json:"ip"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	}
	ip := s.clientIP(r)
	if strings.TrimSpace(body.IP) != "" {
		ip = canonicalIP(body.IP)
	}
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ip"})
		return
	}
	if err := s.grantDynamic(ip); err != nil {
		log.Printf("api grant %s: %v", ip, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ip": ip, "status": "granted"})
}

// checkAPIKey validates the bearer token in constant time.
func (s *Server) checkAPIKey(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if token == h { // no "Bearer " prefix found
		token = h
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.APIKey)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// --- Admin handlers ---

type adminData struct {
	CSRF       string
	Ports      []int
	PortsStr   string
	FixedIPs   []fixedView
	Dynamic    []dynView
	DryRun     bool
	Expiry     string
	AdminIP    string
	Lockout    bool // admin IP is not permanently reachable -> may lock self out
	NumPorts   int
	NumFixed   int
	NumDynamic int
	FWActive    bool // whether ufw is currently enabled
	IPv6Managed bool // whether ufw manages IPv6 (IPV6=yes)
}

type fixedView struct {
	IP     string
	IsSelf bool
}

type dynView struct {
	IP        string
	AddedAt   string // humanized local time
	LastSeen  string
	IdleFor   string // humanized duration, e.g. "3h15m"
	IdleLevel string // "fresh" | "warn" | "danger" — how close to expiry
	IsSelf    bool
}

// humanizeDuration renders a duration compactly: "刚刚", "12分钟", "3小时15分", "2天".
func humanizeDuration(d time.Duration) string {
	if d < time.Minute {
		return "刚刚"
	}
	if d < time.Hour {
		return fmt.Sprintf("%d分钟", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%d小时", h)
		}
		return fmt.Sprintf("%d小时%d分", h, m)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	if h == 0 {
		return fmt.Sprintf("%d天", days)
	}
	return fmt.Sprintf("%d天%d小时", days, h)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Authenticated(r) {
		s.render(w, "login.html", map[string]string{})
		return
	}
	st := s.store.Snapshot()
	adminIP := s.clientIP(r)

	portStrs := make([]string, len(st.Ports))
	for i, p := range st.Ports {
		portStrs[i] = strconv.Itoa(p)
	}

	// Is the admin's IP permanently reachable? (fixed whitelist entry).
	adminFixed := false
	fixed := make([]fixedView, 0, len(st.FixedIPs))
	for _, ip := range st.FixedIPs {
		self := ip == adminIP
		if self {
			adminFixed = true
		}
		fixed = append(fixed, fixedView{IP: ip, IsSelf: self})
	}

	now := time.Now()
	dyn := make([]dynView, 0, len(st.Dynamic))
	for _, d := range st.Dynamic {
		idle := now.Sub(d.LastSeen)
		level := "fresh"
		if s.cfg.Expiry > 0 {
			frac := float64(idle) / float64(s.cfg.Expiry)
			switch {
			case frac >= 0.9:
				level = "danger"
			case frac >= 0.6:
				level = "warn"
			}
		}
		dyn = append(dyn, dynView{
			IP:        d.IP,
			AddedAt:   d.AddedAt.Local().Format("01-02 15:04"),
			LastSeen:  d.LastSeen.Local().Format("01-02 15:04"),
			IdleFor:   humanizeDuration(idle.Truncate(time.Second)),
			IdleLevel: level,
			IsSelf:    d.IP == adminIP,
		})
	}
	sort.Slice(dyn, func(i, j int) bool { return dyn[i].IP < dyn[j].IP })

	s.render(w, "admin.html", adminData{
		CSRF:       s.auth.CSRF(r),
		Ports:      st.Ports,
		PortsStr:   strings.Join(portStrs, ", "),
		FixedIPs:   fixed,
		Dynamic:    dyn,
		DryRun:     s.cfg.DryRun,
		Expiry:     s.cfg.Expiry.String(),
		AdminIP:    adminIP,
		Lockout:    !adminFixed, // not a fixed IP -> access could lapse
		NumPorts:   len(st.Ports),
		NumFixed:   len(st.FixedIPs),
		NumDynamic: len(st.Dynamic),
		FWActive:    s.fw.IsActive(),
		IPv6Managed: s.fw.IPv6Managed(),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.auth.CheckPassword(r.FormValue("password")) {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "login.html", map[string]string{"Error": "invalid password"})
		return
	}
	token, _ := s.auth.NewSession()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Logout(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// requireAdmin guards a mutating admin POST: checks method, auth, and CSRF.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !s.auth.Authenticated(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if !s.auth.CheckCSRF(r, r.FormValue("csrf")) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ports := parsePorts(r.FormValue("ports"))
	if err := s.store.SetPorts(ports); err != nil {
		log.Printf("set ports: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.fw.ReconcileAll(s.store.Snapshot()); err != nil {
		log.Printf("reconcile after ports change: %v", err)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleFixed(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ip := canonicalIP(r.FormValue("ip"))
	action := r.FormValue("action")
	if ip == "" {
		http.Error(w, "invalid IP", http.StatusBadRequest)
		return
	}
	var err error
	switch action {
	case "add":
		err = s.store.AddFixed(ip)
	case "remove":
		err = s.store.RemoveFixed(ip)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("fixed %s %s: %v", action, ip, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.fw.ReconcileAll(s.store.Snapshot()); err != nil {
		log.Printf("reconcile after fixed change: %v", err)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ip := canonicalIP(r.FormValue("ip"))
	if ip == "" {
		http.Error(w, "invalid IP", http.StatusBadRequest)
		return
	}
	if err := s.store.RevokeDynamic(ip); err != nil {
		log.Printf("revoke %s: %v", ip, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.fw.RevokeIP(ip); err != nil {
		log.Printf("revoke firewall %s: %v", ip, err)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// prospectiveState returns the State that would result from applying the given
// admin action to cur, WITHOUT mutating anything. action is one of:
//   "ports"        value = raw ports string
//   "fixed-add"    value = IP      "fixed-remove" value = IP
//   "revoke"       value = IP (removes a dynamic grant)
// It returns an error if value is invalid, so the preview/apply paths validate
// identically.
func prospectiveState(cur State, action, value string) (State, error) {
	next := State{
		Ports:    append([]int(nil), cur.Ports...),
		FixedIPs: append([]string(nil), cur.FixedIPs...),
		Dynamic:  append([]Dynamic(nil), cur.Dynamic...),
	}
	switch action {
	case "ports":
		seen := map[int]bool{}
		clean := []int{}
		for _, p := range parsePorts(value) {
			if p < 1 || p > 65535 || seen[p] {
				continue
			}
			seen[p] = true
			clean = append(clean, p)
		}
		sort.Ints(clean)
		next.Ports = clean
	case "fixed-add":
		ip := canonicalIP(value)
		if ip == "" {
			return next, fmt.Errorf("invalid IP")
		}
		found := false
		for _, e := range next.FixedIPs {
			if e == ip {
				found = true
			}
		}
		if !found {
			next.FixedIPs = append(next.FixedIPs, ip)
			sort.Strings(next.FixedIPs)
		}
	case "fixed-remove":
		ip := canonicalIP(value)
		if ip == "" {
			return next, fmt.Errorf("invalid IP")
		}
		out := next.FixedIPs[:0:0]
		for _, e := range next.FixedIPs {
			if e != ip {
				out = append(out, e)
			}
		}
		next.FixedIPs = out
	case "revoke":
		ip := canonicalIP(value)
		if ip == "" {
			return next, fmt.Errorf("invalid IP")
		}
		out := next.Dynamic[:0:0]
		for _, d := range next.Dynamic {
			if d.IP != ip {
				out = append(out, d)
			}
		}
		next.Dynamic = out
	default:
		return next, fmt.Errorf("unknown action %q", action)
	}
	return next, nil
}

// handlePreview returns a JSON diff of what an action would change in the
// firewall, without applying it. Auth required (read-only, so no CSRF).
//
//	GET /admin/preview?action=ports&value=80,443
//	-> {"current":[...],"add":[...],"delete":[...]}
func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Authenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	action := r.URL.Query().Get("action")
	value := r.URL.Query().Get("value")
	next, err := prospectiveState(s.store.Snapshot(), action, value)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	current, toAdd, toDelete, err := s.fw.Preview(next)
	if err != nil {
		log.Printf("preview: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "无法读取当前防火墙规则"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current": current,
		"add":     toAdd,
		"delete":  toDelete,
	})
}

// handleFirewall is the emergency escape hatch: turn ufw off (restore full
// access) or back on. POST action=disable|enable.
func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	switch r.FormValue("action") {
	case "disable":
		if err := s.fw.Disable(); err != nil {
			log.Printf("firewall disable: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("ufw DISABLED from admin panel (all ports now open)")
	case "enable":
		if err := s.fw.Enable(s.store.Snapshot()); err != nil {
			log.Printf("firewall enable: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		log.Printf("ufw ENABLED from admin panel")
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleIPv6Toggle switches whether ufw manages IPv6 (controls /etc/default/ufw
// IPV6=yes/no, then reloads). POST managed=1 → IPv6 goes through the whitelist
// like IPv4; managed=0 → ufw ignores IPv6 entirely (all IPv6 ports wide open).
func (s *Server) handleIPv6Toggle(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	managed := r.FormValue("managed") == "1"
	if err := s.fw.SetIPv6Managed(managed, s.store.Snapshot()); err != nil {
		log.Printf("set ipv6 managed=%v: %v", managed, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("ufw IPv6 managed = %v (from admin panel)", managed)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// parsePorts accepts comma/space/newline-separated port numbers.
func parsePorts(raw string) []int {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';'
	})
	var ports []int
	for _, f := range fields {
		if n, err := strconv.Atoi(f); err == nil {
			ports = append(ports, n)
		}
	}
	return ports
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

