// mcpgw: a small, dependency-free MCP gateway (Streamable HTTP) with built-in OAuth 2.1
// (DCR + PKCE) for a single operator. It exposes a knowledge-base/tmp file area and
// restricted SSH execution against a fixed allow-list of hosts.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "0.1.0"

// HostCfg describes one SSH target. RO credentials are used for mode=read,
// RW credentials only for mode=write (and uploads).
type HostCfg struct {
	Addr      string `json:"addr"`
	Port      int    `json:"port"`
	Desc      string `json:"desc"`
	ROUser    string `json:"ro_user"`
	ROKey     string `json:"ro_key"`
	RWUser    string `json:"rw_user"`
	RWKey     string `json:"rw_key"`
	SCPLegacy bool   `json:"scp_legacy"` // pass -O to scp (RouterOS-style servers)
}

type Config struct {
	Listen        string             `json:"listen"`
	PublicURL     string             `json:"public_url"` // e.g. https://mc.example.com:29443
	CertFile      string             `json:"cert_file"`
	KeyFile       string             `json:"key_file"`
	KBDir         string             `json:"kb_dir"`
	TmpDir        string             `json:"tmp_dir"`
	StateFile     string             `json:"state_file"`
	AuthFile      string             `json:"auth_file"`
	AuditLog      string             `json:"audit_log"`
	KnownHosts    string             `json:"known_hosts"`
	SSHBin        string             `json:"ssh_bin"`
	SCPBin        string             `json:"scp_bin"`
	APICIDRs      []string           `json:"api_cidrs"`      // who may call /mcp, /token, /register
	LoginCIDRs    []string           `json:"login_cidrs"`    // who may open /authorize
	RedirectAllow []string           `json:"redirect_allow"` // exact redirect URIs accepted at registration
	AllowLoopback bool               `json:"allow_loopback"` // accept http://localhost|127.0.0.1:any/callback
	Hosts         map[string]HostCfg `json:"hosts"`
	DevInsecure   bool               `json:"dev_insecure"` // plain HTTP; only honoured when MCPGW_DEV=1
	TmpMaxAgeDays int                `json:"tmp_max_age_days"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.SSHBin == "" {
		c.SSHBin = "/usr/bin/ssh"
	}
	if c.SCPBin == "" {
		c.SCPBin = "/usr/bin/scp"
	}
	if c.TmpMaxAgeDays == 0 {
		c.TmpMaxAgeDays = 14
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if !strings.HasPrefix(c.PublicURL, "https://") && !(c.DevInsecure && os.Getenv("MCPGW_DEV") == "1") {
		return nil, errors.New("config: public_url must be https://")
	}
	for _, f := range []string{c.KBDir, c.TmpDir, c.StateFile, c.AuthFile, c.AuditLog, c.KnownHosts} {
		if f == "" {
			return nil, errors.New("config: kb_dir, tmp_dir, state_file, auth_file, audit_log, known_hosts are required")
		}
	}
	for name, h := range c.Hosts {
		if h.Addr == "" || h.ROUser == "" || h.ROKey == "" {
			return nil, fmt.Errorf("config: host %q needs addr, ro_user, ro_key", name)
		}
		if (h.RWUser == "") != (h.RWKey == "") {
			return nil, fmt.Errorf("config: host %q: rw_user and rw_key must be set together", name)
		}
		if h.Port == 0 {
			h.Port = 22
			c.Hosts[name] = h
		}
	}
	return &c, nil
}

func parseCIDRs(list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// certCache reloads the TLS certificate when the files change (lego renews them in place).
type certCache struct {
	mu       sync.Mutex
	certFile string
	keyFile  string
	cert     *tls.Certificate
	mtimeC   time.Time
	mtimeK   time.Time
}

func (c *certCache) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sc, err1 := os.Stat(c.certFile)
	sk, err2 := os.Stat(c.keyFile)
	if err1 != nil || err2 != nil {
		if c.cert != nil {
			return c.cert, nil // keep serving the last good certificate
		}
		return nil, errors.New("certificate files unavailable")
	}
	if c.cert == nil || !sc.ModTime().Equal(c.mtimeC) || !sk.ModTime().Equal(c.mtimeK) {
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			if c.cert != nil {
				log.Printf("cert reload failed, keeping previous: %v", err)
				return c.cert, nil
			}
			return nil, err
		}
		c.cert, c.mtimeC, c.mtimeK = &cert, sc.ModTime(), sk.ModTime()
		log.Printf("tls certificate (re)loaded")
	}
	return c.cert, nil
}

func (c *certCache) notAfter() (time.Time, error) {
	cert, err := c.get(nil)
	if err != nil {
		return time.Time{}, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

type App struct {
	cfg       *Config
	auth      *AuthFile
	st        *Store
	audit     *Auditor
	fsys      *FS
	lim       *Limiter
	certs     *certCache
	apiNets   []*net.IPNet
	loginNets []*net.IPNet
	hostLocks sync.Map // host -> *sync.Mutex (serialises write-mode operations)
	started   time.Time
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		os.Exit(runSetup(os.Args[2:]))
	}
	cfgPath := flag.String("config", "/etc/mcpgw/config.json", "config file")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	app := &App{cfg: cfg, started: time.Now()}
	if app.apiNets, err = parseCIDRs(cfg.APICIDRs); err != nil {
		log.Fatal(err)
	}
	if app.loginNets, err = parseCIDRs(cfg.LoginCIDRs); err != nil {
		log.Fatal(err)
	}
	if app.auth, err = loadAuth(cfg.AuthFile); err != nil {
		log.Fatalf("auth file: %v (run: mcpgw setup)", err)
	}
	if app.st, err = openStore(cfg.StateFile); err != nil {
		log.Fatal(err)
	}
	if app.audit, err = openAudit(cfg.AuditLog); err != nil {
		log.Fatal(err)
	}
	if app.fsys, err = openFS(cfg.KBDir, cfg.TmpDir); err != nil {
		log.Fatal(err)
	}
	app.lim = newLimiter()
	app.certs = &certCache{certFile: cfg.CertFile, keyFile: cfg.KeyFile}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go app.maintenance(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      11 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: app.certs.get,
		},
	}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 15*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("mcpgw %s listening on %s (public %s)", version, cfg.Listen, cfg.PublicURL)
	if cfg.DevInsecure && os.Getenv("MCPGW_DEV") == "1" {
		log.Print("WARNING: dev mode, plain HTTP")
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS("", "")
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// maintenance prunes expired tokens/codes and old temp files.
func (a *App) maintenance(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		a.st.gc()
		a.fsys.cleanTmp(time.Duration(a.cfg.TmpMaxAgeDays) * 24 * time.Hour)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
