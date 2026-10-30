package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---- per-IP lockouts (remote logins) ----

// ipKey groups IPv6 clients by /64, IPv4 by address.
func ipKey(ip net.IP) string {
	if ip == nil {
		return "?"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

type ipEntry struct {
	l    *Limiter
	last time.Time
}

// ipLimiter keeps one escalating Limiter per remote client, so a stranger cannot lock the owner out.
type ipLimiter struct {
	mu sync.Mutex
	m  map[string]*ipEntry
}

func newIPLimiter() *ipLimiter { return &ipLimiter{m: map[string]*ipEntry{}} }

func (l *ipLimiter) get(ip net.IP) *Limiter {
	k := ipKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[k]
	if e == nil {
		if len(l.m) >= 20000 { // memory bound: forget idle, unlocked entries
			l.gcLocked(time.Now(), 0)
			if len(l.m) >= 20000 {
				l.m = map[string]*ipEntry{}
			}
		}
		e = &ipEntry{l: newLimiter()}
		l.m[k] = e
	}
	e.last = time.Now()
	return e.l
}

func (l *ipLimiter) gcLocked(now time.Time, idle time.Duration) {
	for k, e := range l.m {
		if locked, _ := e.l.locked(); !locked && now.Sub(e.last) > idle {
			delete(l.m, k)
		}
	}
}

func (l *ipLimiter) gc() {
	l.mu.Lock()
	l.gcLocked(time.Now(), 48*time.Hour)
	l.mu.Unlock()
}

// ---- Cloudflare Turnstile ----

const (
	tsAction  = "login"
	tsDefault = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

type Turnstile struct {
	siteKey, secret, verifyURL string
	hosts                      map[string]bool
	client                     *http.Client
	sem                        chan struct{}
}

// newTurnstile returns nil when no site key is configured (remote logins stay disabled then).
func newTurnstile(c *Config) (*Turnstile, error) {
	if c.TurnstileSiteKey == "" {
		return nil, nil
	}
	b, err := os.ReadFile(c.TurnstileSecretFile)
	if err != nil {
		return nil, fmt.Errorf("turnstile secret: %w", err)
	}
	secret := strings.TrimSpace(string(b))
	if secret == "" {
		return nil, errors.New("turnstile secret file is empty")
	}
	hosts := map[string]bool{}
	for _, h := range c.TurnstileHostnames {
		hosts[strings.ToLower(h)] = true
	}
	if len(hosts) == 0 {
		if u, err := url.Parse(c.PublicURL); err == nil && u.Hostname() != "" {
			hosts[strings.ToLower(u.Hostname())] = true
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("turnstile: no expected hostname")
	}
	v := c.TurnstileVerifyURL
	if v == "" {
		v = tsDefault
	}
	return &Turnstile{siteKey: c.TurnstileSiteKey, secret: secret, verifyURL: v, hosts: hosts,
		client: &http.Client{Timeout: 10 * time.Second}, sem: make(chan struct{}, 4)}, nil
}

// verify validates a widget token server-side. The error text is for the audit log, never for the client.
func (t *Turnstile) verify(ctx context.Context, token string, ip net.IP) error {
	if token == "" || len(token) > 2048 {
		return errors.New("missing or oversized token")
	}
	select {
	case t.sem <- struct{}{}:
		defer func() { <-t.sem }()
	case <-time.After(3 * time.Second):
		return errors.New("verifier busy")
	}
	form := url.Values{"secret": {t.secret}, "response": {token}}
	if ip != nil {
		form.Set("remoteip", ip.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("siteverify unreachable: %v", shortErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("siteverify http %d", resp.StatusCode)
	}
	var r struct {
		Success  bool     `json:"success"`
		Action   string   `json:"action"`
		Hostname string   `json:"hostname"`
		Errors   []string `json:"error-codes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r); err != nil {
		return errors.New("siteverify: bad response")
	}
	switch {
	case !r.Success:
		return fmt.Errorf("rejected: %s", strings.Join(r.Errors, ","))
	case r.Action != tsAction:
		return fmt.Errorf("action mismatch: %q", r.Action)
	case !t.hosts[strings.ToLower(r.Hostname)]:
		return fmt.Errorf("hostname not allowed: %q", r.Hostname)
	}
	return nil
}

// ---- login policy shared by /authorize and the web UI ----

func (a *App) isTrusted(ip net.IP) bool { return inNets(ip, a.trustedNets) }

// needCode reports whether a TOTP code is required for this source.
func (a *App) needCode(ip net.IP) bool {
	if !a.auth.needTOTP() {
		return false
	}
	return !(a.isTrusted(ip) && a.cfg.trustedSkipTOTP())
}

// remoteReady reports whether non-trusted sources may log in at all: CAPTCHA is always required,
// TOTP too unless remote_require_totp is switched off.
func (a *App) remoteReady() bool {
	return a.ts != nil && (a.auth.needTOTP() || !a.cfg.remoteRequireTOTP())
}

// checkLogin applies the whole login policy. It returns an HTTP status (0 = success) and a user-safe message.
func (a *App) checkLogin(ctx context.Context, r *http.Request, pass, code, tsToken string, ui bool) (int, string) {
	ip := clientIP(r)
	ipS := ip.String()
	ev := func(name string, extra map[string]any) {
		m := map[string]any{"ev": name, "ip": ipS, "ui": ui}
		for k, v := range extra {
			m[k] = v
		}
		a.audit.log(m)
	}
	if a.isTrusted(ip) {
		if locked, d := a.lim.locked(); locked {
			ev("login_locked", nil)
			return 429, fmt.Sprintf("Too many failed attempts. Try again in %d min.", int(d.Minutes())+1)
		}
		if !a.auth.verify(pass, code, !a.needCode(ip)) {
			ev("login_fail", map[string]any{"lockout": a.lim.fail()})
			time.Sleep(time.Second)
			return 401, "Invalid credentials."
		}
		a.lim.ok()
		ev("login_ok", map[string]any{"remote": false})
		return 0, ""
	}

	// remote source: TOTP and CAPTCHA are mandatory, failures are counted per client address
	if !a.remoteReady() {
		ev("login_remote_disabled", nil)
		return 403, "Login from this network is not enabled."
	}
	il := a.ipl.get(ip)
	if locked, d := il.locked(); locked {
		ev("login_locked", map[string]any{"remote": true})
		return 429, fmt.Sprintf("Too many failed attempts. Try again in %d min.", int(d.Minutes())+1)
	}
	if err := a.ts.verify(ctx, tsToken, ip); err != nil {
		ev("login_captcha_fail", map[string]any{"remote": true, "reason": err.Error(), "lockout": il.fail()})
		return 400, "CAPTCHA check failed. Reload the page and try again."
	}
	select {
	case a.vsem <- struct{}{}:
		defer func() { <-a.vsem }()
	default:
		return 429, "Server is busy. Try again in a moment."
	}
	if !a.auth.verify(pass, code, false) {
		ev("login_fail", map[string]any{"remote": true, "lockout": il.fail()})
		time.Sleep(time.Second)
		return 401, "Invalid credentials."
	}
	il.ok()
	ev("login_ok", map[string]any{"remote": true})
	return 0, ""
}

// ---- connection limits ----

type limitListener struct {
	net.Listener
	mu       sync.Mutex
	per      map[string]int
	total    int
	maxPer   int
	maxTotal int
}

func newLimitListener(l net.Listener, maxPer, maxTotal int) *limitListener {
	return &limitListener{Listener: l, per: map[string]int{}, maxPer: maxPer, maxTotal: maxTotal}
}

type limConn struct {
	net.Conn
	l    *limitListener
	ip   string
	once sync.Once
}

func (c *limConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.per[c.ip]--
		if c.l.per[c.ip] <= 0 {
			delete(c.l.per, c.ip)
		}
		c.l.total--
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		h, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		k := ipKey(net.ParseIP(h))
		l.mu.Lock()
		if l.total >= l.maxTotal || l.per[k] >= l.maxPer {
			l.mu.Unlock()
			_ = c.Close()
			continue
		}
		l.per[k]++
		l.total++
		l.mu.Unlock()
		return &limConn{Conn: c, l: l, ip: k}, nil
	}
}
