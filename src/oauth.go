package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	accessTTL  = time.Hour
	refreshTTL = 30 * 24 * time.Hour
	codeTTL    = 60 * time.Second
	maxClients = 100
)

type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Created      int64    `json:"created"`
}

type Token struct {
	Kind     string `json:"kind"` // "access" | "refresh"
	ClientID string `json:"client_id"`
	Family   string `json:"family"`
	Exp      int64  `json:"exp"`
	Used     bool   `json:"used,omitempty"`
}

type authCode struct {
	ClientID, RedirectURI, Challenge string
	Exp                              time.Time
}

type pendingAuth struct {
	ClientID, RedirectURI, Challenge, State string
	Exp                                     time.Time
	Tries                                   int
}

type Store struct {
	mu      sync.Mutex
	path    string
	Clients map[string]*Client `json:"clients"`
	Tokens  map[string]*Token  `json:"tokens"` // key: sha256(token)
	codes   map[string]*authCode
	pending map[string]*pendingAuth
}

func openStore(path string) (*Store, error) {
	s := &Store{path: path, Clients: map[string]*Client{}, Tokens: map[string]*Token{},
		codes: map[string]*authCode{}, pending: map[string]*pendingAuth{}}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("state file: %w", err)
		}
		if s.Clients == nil {
			s.Clients = map[string]*Client{}
		}
		if s.Tokens == nil {
			s.Tokens = map[string]*Token{}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// saveLocked persists clients and tokens atomically. Caller holds s.mu.
func (s *Store) saveLocked() {
	b, _ := json.Marshal(struct {
		Clients map[string]*Client `json:"clients"`
		Tokens  map[string]*Token  `json:"tokens"`
	}{s.Clients, s.Tokens})
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func (s *Store) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, t := range s.Tokens {
		if t.Exp < now.Unix() {
			delete(s.Tokens, k)
		}
	}
	for k, c := range s.codes {
		if now.After(c.Exp) {
			delete(s.codes, k)
		}
	}
	for k, p := range s.pending {
		if now.After(p.Exp) {
			delete(s.pending, k)
		}
	}
	s.saveLocked()
}

func (s *Store) revokeFamilyLocked(fam string) {
	for k, t := range s.Tokens {
		if t.Family == fam {
			delete(s.Tokens, k)
		}
	}
}

func (s *Store) issueLocked(clientID, family string) (access, refresh string) {
	access, refresh = randToken(32), randToken(32)
	s.Tokens[sha(access)] = &Token{Kind: "access", ClientID: clientID, Family: family, Exp: time.Now().Add(accessTTL).Unix()}
	s.Tokens[sha(refresh)] = &Token{Kind: "refresh", ClientID: clientID, Family: family, Exp: time.Now().Add(refreshTTL).Unix()}
	return
}

// checkBearer validates an access token and returns its client id.
func (s *Store) checkBearer(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.Tokens[sha(tok)]
	if !ok || t.Kind != "access" || t.Exp < time.Now().Unix() {
		return "", false
	}
	return t.ClientID, true
}

func clientIP(r *http.Request) net.IP {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	return net.ParseIP(h)
}

func inNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// gate rejects requests whose source address is outside nets.
func (a *App) gate(nets []*net.IPNet, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !inNets(clientIP(r), nets) {
			a.logDeny(clientIP(r), r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		hd.Set("Strict-Transport-Security", "max-age=31536000")
		hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, code int, e, desc string) {
	writeJSON(w, code, map[string]string{"error": e, "error_description": desc})
}

func (a *App) metaResource(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource":                 a.cfg.PublicURL + "/mcp",
		"authorization_servers":    []string{a.cfg.PublicURL},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp"},
	})
}

func (a *App) metaAS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":                                a.cfg.PublicURL,
		"authorization_endpoint":                a.cfg.LoginURL + "/authorize",
		"token_endpoint":                        a.cfg.PublicURL + "/token",
		"registration_endpoint":                 a.cfg.PublicURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
	})
}

func (a *App) redirectAllowed(uri string) bool {
	for _, u := range a.cfg.RedirectAllow {
		if u == uri {
			return true
		}
	}
	if a.cfg.AllowLoopback {
		u, err := url.Parse(uri)
		if err == nil && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1") && u.Path == "/callback" && u.RawQuery == "" && u.Fragment == "" {
			return true
		}
	}
	return false
}

func (a *App) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthErr(w, 405, "invalid_request", "POST required")
		return
	}
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 5 {
		oauthErr(w, 400, "invalid_client_metadata", "redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !a.redirectAllowed(u) {
			a.audit.log(map[string]any{"ev": "register_rejected", "redirect": u, "ip": clientIP(r).String()})
			oauthErr(w, 400, "invalid_redirect_uri", "redirect_uri is not allowed")
			return
		}
	}
	name := req.ClientName
	if len(name) > 80 {
		name = name[:80]
	}
	c := &Client{ID: randToken(18), Name: name, RedirectURIs: req.RedirectURIs, Created: time.Now().Unix()}
	a.st.mu.Lock()
	if len(a.st.Clients) >= maxClients { // evict the oldest clients
		type kv struct {
			k string
			t int64
		}
		var all []kv
		for k, v := range a.st.Clients {
			all = append(all, kv{k, v.Created})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].t < all[j].t })
		for _, e := range all[:len(all)-maxClients+1] {
			delete(a.st.Clients, e.k)
		}
	}
	a.st.Clients[c.ID] = c
	a.st.saveLocked()
	a.st.mu.Unlock()
	a.audit.log(map[string]any{"ev": "register", "client": c.ID, "name": c.Name})
	writeJSON(w, 201, map[string]any{
		"client_id": c.ID, "client_id_issued_at": c.Created, "client_name": c.Name,
		"redirect_uris": c.RedirectURIs, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	})
}

const loginPage = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize</title><style>body{font:16px system-ui,sans-serif;max-width:26rem;margin:3rem auto;padding:0 1rem}
input,button{width:100%%;padding:.7rem;margin:.4rem 0;font-size:1rem;box-sizing:border-box}.e{color:#b00020}code{background:#eee;padding:0 .3rem}</style></head>
<body><h2>Authorize access</h2><p>Client <b>%s</b> requests access to this MCP gateway.<br>Redirect host: <code>%s</code></p>%s
<form method="post" action="/authorize"><input type="hidden" name="rid" value="%s">
<input type="password" name="pass" placeholder="Passphrase" autocomplete="current-password" required>
%s<button type="submit">Authorize</button></form>%s</body></html>`

// tsCSP is the page policy when the Turnstile widget is shown.
const tsCSP = "default-src 'none'; style-src 'unsafe-inline'; script-src https://challenges.cloudflare.com; " +
	"frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; frame-ancestors 'none'"

func (a *App) renderLogin(w http.ResponseWriter, r *http.Request, status int, p *pendingAuth, rid, msg string) {
	a.st.mu.Lock()
	cl := a.st.Clients[p.ClientID]
	a.st.mu.Unlock()
	name, host := "(unknown)", ""
	if cl != nil {
		name = cl.Name
	}
	if u, err := url.Parse(p.RedirectURI); err == nil {
		host = u.Host
	}
	if msg != "" {
		msg = `<p class="e">` + html.EscapeString(msg) + `</p>`
	}
	ip := clientIP(r)
	field, widget := "", ""
	if a.needCode(ip) {
		field = `<input name="totp" placeholder="6-digit code" inputmode="numeric" autocomplete="one-time-code" required>` + "\n"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !a.isTrusted(ip) && a.ts != nil {
		w.Header().Set("Content-Security-Policy", tsCSP)
		field += `<div class="cf-turnstile" data-sitekey="` + html.EscapeString(a.ts.siteKey) + `" data-action="` + tsAction + `" data-theme="auto"></div>` + "\n"
		widget = `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, loginPage, html.EscapeString(name), html.EscapeString(host), msg, html.EscapeString(rid), field, widget)
}

func (a *App) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		a.authorizePost(w, r)
		return
	}
	q := r.URL.Query()
	a.st.mu.Lock()
	cl := a.st.Clients[q.Get("client_id")]
	a.st.mu.Unlock()
	red := q.Get("redirect_uri")
	okRed := false
	if cl != nil {
		for _, u := range cl.RedirectURIs {
			if u == red {
				okRed = true
			}
		}
	}
	if cl == nil || !okRed {
		http.Error(w, "invalid client or redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "response_type=code and PKCE S256 are required", http.StatusBadRequest)
		return
	}
	if !a.isTrusted(clientIP(r)) && !a.remoteReady() {
		a.audit.log(map[string]any{"ev": "login_remote_disabled", "ip": clientIP(r).String(), "ui": false})
		http.Error(w, "Login from this network is not enabled.", http.StatusForbidden)
		return
	}
	p := &pendingAuth{ClientID: cl.ID, RedirectURI: red, Challenge: q.Get("code_challenge"), State: q.Get("state"), Exp: time.Now().Add(10 * time.Minute)}
	rid := randToken(24)
	a.st.mu.Lock()
	if len(a.st.pending) > 100 { // drop expired entries first, then everything as a last resort
		now := time.Now()
		for k, v := range a.st.pending {
			if now.After(v.Exp) {
				delete(a.st.pending, k)
			}
		}
		if len(a.st.pending) > 200 {
			a.st.pending = map[string]*pendingAuth{}
		}
	}
	a.st.pending[rid] = p
	a.st.mu.Unlock()
	a.renderLogin(w, r, 200, p, rid, "")
}

func (a *App) authorizePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	rid := r.PostForm.Get("rid")
	a.st.mu.Lock()
	p := a.st.pending[rid]
	a.st.mu.Unlock()
	if p == nil || time.Now().After(p.Exp) {
		http.Error(w, "request expired, start again", http.StatusBadRequest)
		return
	}
	pass, totp, tsTok := r.PostForm.Get("pass"), r.PostForm.Get("totp"), r.PostForm.Get("cf-turnstile-response")
	if st, msg := a.checkLogin(r.Context(), r, pass, totp, tsTok, false); st != 0 {
		if st == 400 || st == 401 { // every failed attempt spends one of the five tries of this login request
			a.st.mu.Lock()
			p.Tries++
			if p.Tries >= 5 {
				delete(a.st.pending, rid)
			}
			a.st.mu.Unlock()
		}
		a.renderLogin(w, r, st, p, rid, msg)
		return
	}
	code := randToken(32)
	a.st.mu.Lock()
	delete(a.st.pending, rid)
	a.st.codes[sha(code)] = &authCode{ClientID: p.ClientID, RedirectURI: p.RedirectURI, Challenge: p.Challenge, Exp: time.Now().Add(codeTTL)}
	a.st.mu.Unlock()
	a.audit.log(map[string]any{"ev": "code_issued", "ip": clientIP(r).String(), "client": p.ClientID})
	u, _ := url.Parse(p.RedirectURI)
	qq := u.Query()
	qq.Set("code", code)
	if p.State != "" {
		qq.Set("state", p.State)
	}
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *App) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthErr(w, 405, "invalid_request", "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthErr(w, 400, "invalid_request", "bad form")
		return
	}
	f := r.PostForm
	switch f.Get("grant_type") {
	case "authorization_code":
		a.st.mu.Lock()
		defer a.st.mu.Unlock()
		k := sha(f.Get("code"))
		c := a.st.codes[k]
		delete(a.st.codes, k) // single use
		if c == nil || time.Now().After(c.Exp) || c.ClientID != f.Get("client_id") || c.RedirectURI != f.Get("redirect_uri") {
			oauthErr(w, 400, "invalid_grant", "code invalid or expired")
			return
		}
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(c.Challenge)) != 1 {
			oauthErr(w, 400, "invalid_grant", "PKCE verification failed")
			return
		}
		acc, ref := a.st.issueLocked(c.ClientID, randToken(9))
		a.st.saveLocked()
		a.audit.log(map[string]any{"ev": "token_issued", "client": c.ClientID, "ip": clientIP(r).String()})
		writeJSON(w, 200, map[string]any{"access_token": acc, "token_type": "Bearer", "expires_in": int(accessTTL.Seconds()), "refresh_token": ref, "scope": "mcp"})
	case "refresh_token":
		a.st.mu.Lock()
		defer a.st.mu.Unlock()
		k := sha(f.Get("refresh_token"))
		t := a.st.Tokens[k]
		if t == nil || t.Kind != "refresh" || t.Exp < time.Now().Unix() || t.ClientID != f.Get("client_id") {
			oauthErr(w, 400, "invalid_grant", "refresh token invalid or expired")
			return
		}
		if t.Used { // reuse of a rotated token: revoke the whole family
			a.st.revokeFamilyLocked(t.Family)
			a.st.saveLocked()
			a.audit.log(map[string]any{"ev": "refresh_reuse_revoked", "client": t.ClientID, "ip": clientIP(r).String()})
			oauthErr(w, 400, "invalid_grant", "refresh token reuse detected")
			return
		}
		t.Used = true
		acc, ref := a.st.issueLocked(t.ClientID, t.Family)
		a.st.saveLocked()
		writeJSON(w, 200, map[string]any{"access_token": acc, "token_type": "Bearer", "expires_in": int(accessTTL.Seconds()), "refresh_token": ref, "scope": "mcp"})
	default:
		oauthErr(w, 400, "unsupported_grant_type", "authorization_code or refresh_token")
	}
}

// bearer extracts the token from the Authorization header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

var _ = filepath.Join

// logDeny records a blocked source at most once per 10 minutes per address, so scanners cannot flood the audit log.
func (a *App) logDeny(ip net.IP, path string) {
	k := ipKey(ip)
	now := time.Now()
	if v, ok := a.denyLog.Load(k); ok && now.Sub(v.(time.Time)) < 10*time.Minute {
		return
	}
	a.denyLog.Store(k, now)
	a.audit.log(map[string]any{"ev": "deny_ip", "ip": ip.String(), "path": path})
}
