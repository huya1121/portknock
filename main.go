package main

import (
	"crypto/subtle"
	"crypto/tls"
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
	"path/filepath"
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
	APIKey     string
	GrantPass  string // optional password the user page requires before granting
}

// Server bundles the handlers' dependencies.
type Server struct {
	cfg    Config
	store  *Store
	fw     *Firewall
	auth   *Auth
	syncer *Syncer
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
	flag.StringVar(&cfg.APIKey, "api-key", "", "bearer token for the JSON API (or env PORTKNOCK_API_KEY); empty disables the API")
	flag.StringVar(&cfg.GrantPass, "grant-pass", "", "password the user page requires before granting (or env PORTKNOCK_GRANT_PASSWORD); empty = no password")
	flag.Parse()

	if cfg.AdminPass == "" {
		cfg.AdminPass = os.Getenv("PORTKNOCK_ADMIN_PASS")
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("PORTKNOCK_API_KEY")
	}
	if cfg.GrantPass == "" {
		cfg.GrantPass = os.Getenv("PORTKNOCK_GRANT_PASSWORD")
	}
	if cfg.AdminPass == "" {
		log.Fatal("admin password required: set --admin-pass or PORTKNOCK_ADMIN_PASS")
	}

	store, err := NewStore(cfg.StatePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}
	fw := NewFirewall(cfg.DryRun)
	syncer := NewSyncer(store)
	srv := &Server{
		cfg:    cfg,
		store:  store,
		fw:     fw,
		auth:   NewAuth(cfg.AdminPass, 12*time.Hour),
		syncer: syncer,
	}

	// Reconcile firewall to match persisted state at startup.
	if err := fw.ReconcileAll(store.Snapshot()); err != nil {
		log.Printf("startup reconcile: %v", err)
	}

	// Start the janitor (conntrack-based idle expiry) and the syncer keep-alive
	// loop (re-push whitelist to children on its own, admin-configurable interval).
	janitor := NewJanitor(store, fw, cfg.Poll, cfg.Expiry)
	stop := make(chan struct{})
	go janitor.Run(stop)
	go syncer.RunKeepAlive(stop, cfg.Poll)

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/grant", srv.handleGrant)
	mux.HandleFunc("/admin", srv.handleAdmin)
	mux.HandleFunc("/admin/login", srv.handleLogin)
	mux.HandleFunc("/admin/logout", srv.handleLogout)
	mux.HandleFunc("/admin/ports", srv.handlePorts)
	mux.HandleFunc("/admin/sync-ports", srv.handleSyncPorts)
	mux.HandleFunc("/admin/fixed", srv.handleFixed)
	mux.HandleFunc("/admin/revoke", srv.handleRevoke)
	mux.HandleFunc("/admin/preview", srv.handlePreview)
	mux.HandleFunc("/admin/firewall", srv.handleFirewall)
	mux.HandleFunc("/admin/ipv6", srv.handleIPv6Toggle)
	mux.HandleFunc("/admin/children", srv.handleChildren)
	mux.HandleFunc("/admin/sync-interval", srv.handleSyncInterval)
	mux.HandleFunc("/admin/node-mode", srv.handleNodeMode)
	mux.HandleFunc("/admin/upgrade", srv.handleUpgradeSelf)
	mux.HandleFunc("/admin/upgrade-children", srv.handleUpgradeChildren)
	mux.HandleFunc("/admin/allow-remote-upgrade", srv.handleAllowRemoteUpgrade)
	mux.HandleFunc("/api/grant", srv.handleAPIGrant)
	mux.HandleFunc("/api/ports", srv.handleAPIPorts)
	mux.HandleFunc("/api/upgrade", srv.handleAPIUpgrade)
	mux.HandleFunc("/api/info", srv.handleAPIInfo)

	// HTTPS only, with an auto-generated self-signed cert kept next to the state
	// file. Browsers warn on the self-signed cert, but all traffic (admin
	// password, API keys, node-to-node sync) is encrypted.
	certDir := filepath.Dir(cfg.StatePath)
	cert, err := ensureSelfSignedCert(certDir)
	if err != nil {
		log.Fatalf("tls cert: %v", err)
	}
	srvHTTP := &http.Server{
		Addr:      cfg.Listen,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	log.Printf("portknock %s listening on https://%s (%s, dry-run=%v, expiry=%s, poll=%s, api=%v)",
		version, cfg.Listen, certInfo(cert), cfg.DryRun, cfg.Expiry, cfg.Poll, cfg.APIKey != "")
	// Cert/key are already in TLSConfig, so pass empty paths.
	if err := srvHTTP.ListenAndServeTLS("", ""); err != nil {
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
	ClientIP   string
	Ports      []int
	Granted    bool
	Error      string
	CSRF       string
	NeedPass   bool   // user page should show a password field
	Version    string // build version, shown in the footer
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
		Secure:   true, // service is HTTPS-only
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
		Ports:    allOpenPorts(st), // all open ports (local + synced + received)
		Granted:  r.URL.Query().Get("granted") == "1",
		Error:    r.URL.Query().Get("err"),
		CSRF:     s.grantToken(w, r),
		NeedPass: s.cfg.GrantPass != "",
		Version:  version,
	}
	s.render(w, "index.html", data)
}

// grantDynamic records a dynamic (all-port) grant for ip and installs its ufw
// rule. ip must already be validated by the caller. If the firewall rule cannot
// be installed, the store grant is rolled back so the UI never shows an IP as
// granted while it has no actual access.
//
// fanOut controls whether the grant is forwarded to child nodes. Pass true for
// an original user submission (web page / local), false for a grant that
// arrived FROM another node via /api/grant — otherwise two nodes that list each
// other as children would push the same IP back and forth forever. This caps
// propagation at a single hop and makes any topology (even A⇄B) loop-safe.
func (s *Server) grantDynamic(ip string, fanOut bool) error {
	added, err := s.store.Grant(ip, time.Now())
	if err != nil {
		return err
	}
	// Only touch ufw / log when this is a NEW grant. A refresh (keep-alive
	// re-push of an already-granted IP) just bumped LastSeen above; re-running
	// ufw would fork a subprocess and spam an identical log line every poll.
	if added {
		if err := s.fw.AllowIP(ip); err != nil {
			if rbErr := s.store.RevokeDynamic(ip); rbErr != nil { // keep state consistent with the firewall
				log.Printf("grant rollback %s: %v", ip, rbErr)
			}
			return fmt.Errorf("install firewall rule: %w", err)
		}
		log.Printf("granted dynamic all-port access to %s", ip)
	}
	// Only forward originals, in the background (never blocks the caller;
	// failures are retried on the next janitor keep-alive).
	if fanOut && s.syncer != nil {
		s.syncer.FanOut(ip)
	}
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
	// Optional shared password gate: when configured, the form must carry the
	// matching password before anything is granted.
	if s.cfg.GrantPass != "" {
		if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(s.cfg.GrantPass)) != 1 {
			http.Redirect(w, r, "/?err=password", http.StatusSeeOther)
			return
		}
	}
	ip := s.clientIP(r)
	if net.ParseIP(ip) == nil {
		http.Error(w, "could not determine a valid client IP", http.StatusBadRequest)
		return
	}
	if err := s.grantDynamic(ip, true); err != nil { // web submission: fan out
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
	// Forward to children UNLESS this request is itself a node-to-node sync push
	// (marked by the syncer). That one-hop cap is what keeps A⇄B from looping.
	isSync := r.Header.Get(syncHeader) != ""
	if isSync && s.syncer != nil {
		// This node is someone's child: remember the pushing center so the admin
		// UI can show it. Uses the connection IP, not body.IP (that's the grantee).
		s.syncer.RecordUpstream(s.clientIP(r))
	}
	if err := s.grantDynamic(ip, !isSync); err != nil {
		log.Printf("api grant %s: %v", ip, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ip": ip, "status": "granted"})
}

// handleAPIPorts is an internal node-to-node endpoint: a center pushes its full
// sync-port list here and this (child) node opens exactly those ports. It is NOT
// a public API — it requires both the API key AND the sync header, so it can
// only be driven by another portknock node's syncer, never by an outside caller.
//
//	POST /api/ports   Authorization: Bearer <key>   X-Portknock-Sync: 1
//	{"ports":[8000,9000]}
func (s *Server) handleAPIPorts(w http.ResponseWriter, r *http.Request) {
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
	// Internal-only: must come from a node-to-node sync push.
	if r.Header.Get(syncHeader) == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "sync endpoint"})
		return
	}
	var body struct {
		Ports []int `json:"ports"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	}
	if s.syncer != nil {
		s.syncer.RecordUpstream(s.clientIP(r))
	}
	if err := s.store.SetReceivedPorts(body.Ports); err != nil {
		log.Printf("api ports: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if err := s.fw.ReconcileAll(s.store.Snapshot()); err != nil {
		log.Printf("reconcile after received-ports change: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ports": s.store.Snapshot().ReceivedPorts, "status": "ok"})
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
	CSRF         string
	Ports        []int
	PortsStr     string
	SyncPorts    []int  // ports distributed to children (center side)
	SyncPortsStr string // comma-joined, for the form input
	ReceivedPorts []int // ports received from an upstream center (child side)
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
	Children    []childView
	Upstreams   []upstreamView // centers that push sync grants to this node
	IsCenter    bool           // effective role is center -> show center controls
	NodeMode    string         // raw override: "center" | "child" | "" (auto)
	HasUpstream bool           // some upstream has pushed to us (for auto-mode hint)
	AllowRemoteUpgrade bool    // this node accepts remote upgrade pushes
	UpgradeMsg  string         // transient banner after an upgrade action ("" = none)
	SyncInterval    string     // human-readable keep-alive interval, e.g. "2分钟"
	SyncIntervalSec int        // the same as seconds, for the form input value
	APIKey      string         // JSON API bearer token ("" = API disabled)
	APIBase     string         // base URL for API examples, e.g. http://host:8080
	Version     string         // build version, shown in the footer
}

// childView is a child node plus its last-sync status, for the admin table.
type childView struct {
	URL     string
	Status  string // "ok" | "fail" | "unknown"
	Detail  string // human-readable last-sync info
	Version string // child's reported version ("" = unknown)
}

// upstreamView is an upstream center (a node that has pushed sync grants to us).
type upstreamView struct {
	IP     string
	Detail string // humanized "last pushed X ago"
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
	syncPortStrs := make([]string, len(st.SyncPorts))
	for i, p := range st.SyncPorts {
		syncPortStrs[i] = strconv.Itoa(p)
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

	// Child nodes + their last-sync status.
	syncStatus := s.syncer.Status()
	children := make([]childView, 0, len(st.Children))
	for _, c := range st.Children {
		cv := childView{URL: c.URL, Status: "unknown", Detail: "尚未推送"}
		if st, ok := syncStatus[c.URL]; ok {
			cv.Version = st.Version
			if !st.When.IsZero() {
				when := st.When.Local().Format("01-02 15:04")
				if st.OK {
					cv.Status = "ok"
					cv.Detail = "最近同步 " + when + " 成功"
				} else {
					cv.Status = "fail"
					cv.Detail = "最近同步 " + when + " 失败：" + st.Err
				}
			}
		}
		children = append(children, cv)
	}

	// Upstream centers (nodes that have pushed sync grants to us) — tells the
	// admin of a child node who it is downstream of.
	upMap := s.syncer.Upstreams()
	upstreams := make([]upstreamView, 0, len(upMap))
	for ip, when := range upMap {
		upstreams = append(upstreams, upstreamView{
			IP:     ip,
			Detail: "最近 " + when.Local().Format("01-02 15:04") + "（" + humanizeDuration(now.Sub(when).Truncate(time.Second)) + "前）推送",
		})
	}
	sort.Slice(upstreams, func(i, j int) bool { return upstreams[i].IP < upstreams[j].IP })

	// Base URL for API examples: derive scheme from how we're reached.
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	apiBase := scheme + "://" + r.Host

	syncIv := s.store.SyncIntervalOr(s.cfg.Poll)
	isCenter := s.syncer.EffectiveMode() == "center"
	var upgradeMsg string
	switch r.URL.Query().Get("upgrade") {
	case "started":
		upgradeMsg = "✅ 升级已在后台开始：正在下载最新版本并重启服务，稍候片刻刷新页面。"
	case "failed":
		upgradeMsg = "⚠️ 升级未能启动（可能本机未安装 portknock-ctl / 非一键安装部署）。详见服务日志。"
	case "children":
		upgradeMsg = "✅ 已向所有子节点发送升级请求（仅对已开启“允许远程升级”的子节点生效）。"
	}

	s.render(w, "admin.html", adminData{
		CSRF:          s.auth.CSRF(r),
		Ports:         st.Ports,
		PortsStr:      strings.Join(portStrs, ", "),
		SyncPorts:     st.SyncPorts,
		SyncPortsStr:  strings.Join(syncPortStrs, ", "),
		ReceivedPorts: st.ReceivedPorts,
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
		Children:    children,
		Upstreams:   upstreams,
		IsCenter:    isCenter,
		NodeMode:    st.NodeMode,
		HasUpstream: len(upstreams) > 0,
		AllowRemoteUpgrade: st.AllowRemoteUpgrade,
		UpgradeMsg:  upgradeMsg,
		SyncInterval:    humanizeDuration(syncIv),
		SyncIntervalSec: int(syncIv.Seconds()),
		APIKey:      s.cfg.APIKey,
		APIBase:     apiBase,
		Version:     version,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := s.clientIP(r)
	// Throttle brute force: refuse while this IP is locked out.
	if locked, left := s.auth.Locked(ip); locked {
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, "login.html", map[string]string{
			"Error": fmt.Sprintf("尝试过多，请 %s 后再试。", left),
		})
		return
	}
	if !s.auth.CheckPassword(r.FormValue("password")) {
		s.auth.RecordFail(ip)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "login.html", map[string]string{"Error": "invalid password"})
		return
	}
	s.auth.RecordSuccess(ip)
	token, _ := s.auth.NewSession()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // service is HTTPS-only
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

// handleSyncPorts sets the open ports this node distributes to its children.
// They're opened locally too, and pushed to every child immediately.
func (s *Server) handleSyncPorts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ports := parsePorts(r.FormValue("ports"))
	if err := s.store.SetSyncPorts(ports); err != nil {
		log.Printf("set sync ports: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.fw.ReconcileAll(s.store.Snapshot()); err != nil {
		log.Printf("reconcile after sync-ports change: %v", err)
	}
	// Push the new list to children right away (don't wait for the janitor pass).
	if s.syncer != nil {
		s.syncer.FanOutPorts()
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
	// Adding a fixed IP also fans it out to child nodes (they grant it as a
	// dynamic IP, kept alive by the janitor). Removal is not propagated — child
	// grants simply idle out on their own.
	if action == "add" && s.syncer != nil {
		s.syncer.FanOut(ip)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleChildren manages downstream nodes this one fans grants out to.
// POST action=add (url+key) | remove (url).
func (s *Server) handleChildren(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	action := r.FormValue("action")
	// Normalize: strip trailing slashes and an accidentally-pasted "/api/grant"
	// so we store a clean origin and never build "…/api/grant/api/grant".
	url := childBase(r.FormValue("url"))
	var err error
	switch action {
	case "add":
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			http.Error(w, "节点地址需以 http:// 或 https:// 开头", http.StatusBadRequest)
			return
		}
		key := strings.TrimSpace(r.FormValue("key"))
		if key == "" {
			http.Error(w, "缺少该节点的 API 密钥", http.StatusBadRequest)
			return
		}
		err = s.store.AddChild(url, key)
	case "remove":
		err = s.store.RemoveChild(url)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("children %s %s: %v", action, url, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Newly added child: immediately push the full current whitelist to it in the
	// background, so it's in sync within seconds instead of waiting for the next
	// janitor keep-alive pass.
	if action == "add" && s.syncer != nil {
		s.syncer.FanOutAll()
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleSyncInterval sets the child keep-alive re-push interval. Accepts a plain
// number of seconds or a Go duration (e.g. "30s", "2m"); clamped to [10s, 24h].
// Takes effect on the syncer's next keep-alive tick (no restart needed).
func (s *Server) handleSyncInterval(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	raw := strings.TrimSpace(r.FormValue("interval"))
	var d time.Duration
	if n, err := strconv.Atoi(raw); err == nil {
		d = time.Duration(n) * time.Second // bare number = seconds
	} else if pd, err := time.ParseDuration(raw); err == nil {
		d = pd
	} else {
		http.Error(w, "间隔格式无效（填秒数，或如 30s / 2m）", http.StatusBadRequest)
		return
	}
	if d > 24*time.Hour {
		d = 24 * time.Hour
	}
	// SetSyncInterval clamps the lower bound to 10s.
	if err := s.store.SetSyncInterval(d); err != nil {
		log.Printf("set sync interval: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleNodeMode sets the node role override: "center", "child", or "" (auto).
// Switching to child mode stops outbound sync (enforced in the syncer).
func (s *Server) handleNodeMode(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	mode := strings.TrimSpace(r.FormValue("mode"))
	if err := s.store.SetNodeMode(mode); err != nil {
		http.Error(w, "无效的节点模式", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleUpgradeSelf triggers a local upgrade (re-download latest + restart) by
// running the installed management script in the background.
func (s *Server) handleUpgradeSelf(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := runSelfUpgrade(); err != nil {
		log.Printf("self upgrade: %v", err)
		http.Redirect(w, r, "/admin?upgrade=failed#cluster", http.StatusSeeOther)
		return
	}
	log.Printf("self upgrade triggered by admin %s", s.clientIP(r))
	http.Redirect(w, r, "/admin?upgrade=started#cluster", http.StatusSeeOther)
}

// handleUpgradeChildren (center only) remotely triggers every child node to
// upgrade itself, via each child's /api/upgrade endpoint.
func (s *Server) handleUpgradeChildren(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if s.syncer != nil {
		// Empty list = all children; otherwise only the checked ones.
		s.syncer.UpgradeChildren(r.Form["child"])
	}
	http.Redirect(w, r, "/admin?upgrade=children#cluster", http.StatusSeeOther)
}

// handleAllowRemoteUpgrade toggles whether this node accepts remote upgrade
// pushes from an upstream center (the /api/upgrade gate). Default off.
func (s *Server) handleAllowRemoteUpgrade(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	allow := r.FormValue("allow") == "1"
	if err := s.store.SetAllowRemoteUpgrade(allow); err != nil {
		log.Printf("set allow-remote-upgrade: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// handleAPIUpgrade is the internal node-to-node endpoint a center calls to make
// this (child) node upgrade itself. THREE gates, all required:
//  1. valid API key (checkAPIKey)
//  2. the node-to-node sync header (never reachable as a plain public call)
//  3. the admin has opted in via AllowRemoteUpgrade (default false)
func (s *Server) handleAPIUpgrade(w http.ResponseWriter, r *http.Request) {
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
	if r.Header.Get(syncHeader) == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "sync endpoint"})
		return
	}
	if !s.store.Snapshot().AllowRemoteUpgrade {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "remote upgrade disabled on this node"})
		return
	}
	if err := runSelfUpgrade(); err != nil {
		log.Printf("api upgrade: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("remote upgrade triggered by upstream %s", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "upgrading"})
}

// handleAPIInfo is a read-only internal endpoint returning this node's version,
// so an upstream center can display it. Gated like the other /api/* endpoints
// (API key + sync header); not exposed to the public.
func (s *Server) handleAPIInfo(w http.ResponseWriter, r *http.Request) {
	if s.cfg.APIKey == "" {
		http.Error(w, "api disabled", http.StatusNotFound)
		return
	}
	if !s.checkAPIKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Header.Get(syncHeader) == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "sync endpoint"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"version": version})
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
	// Don't delete the ufw rule if this IP is also a fixed whitelist entry —
	// they share one `allow from <ip>` rule and the fixed access must survive.
	isFixed := false
	for _, f := range s.store.Snapshot().FixedIPs {
		if f == ip {
			isFixed = true
			break
		}
	}
	if !isFixed {
		if err := s.fw.RevokeIP(ip); err != nil {
			log.Printf("revoke firewall %s: %v", ip, err)
		}
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
		Ports:         append([]int(nil), cur.Ports...),
		FixedIPs:      append([]string(nil), cur.FixedIPs...),
		Dynamic:       append([]Dynamic(nil), cur.Dynamic...),
		SyncPorts:     append([]int(nil), cur.SyncPorts...),
		ReceivedPorts: append([]int(nil), cur.ReceivedPorts...),
	}
	switch action {
	case "ports":
		next.Ports = cleanPorts(parsePorts(value))
	case "sync-ports":
		next.SyncPorts = cleanPorts(parsePorts(value))
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

