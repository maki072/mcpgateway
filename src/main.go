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

const version = "0.2.0"

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
	PublicURL     string             `json:"public_url"` // e.g. https://mc.example.com (what Claude's servers use: must be port 443)
	LoginURL      string             `json:"login_url"`  // base URL opened in the browser for /authorize and /ui (default: public_url)
	CertFile      string             `json:"cert_file"`
	KeyFile       string             `json:"key_file"`
	KBDir         string             `json:"kb_dir"`     // legacy plain-file notes, imported once into the database
	KBDB          string             `json:"kb_db"`      // SQLite knowledge base
	BackupDir     string             `json:"backup_dir"` // snapshots of the database
	TmpDir        string             `json:"tmp_dir"`
	StateFile     string             `json:"state_file"`
	AuthFile      string             `json:"auth_file"`
	AuditLog      string             `json:"audit_log"`
	KnownHosts    string             `json:"known_hosts"`
	SSHBin        string             `json:"ssh_bin"`
	SCPBin        string             `json:"scp_bin"`
	APICIDRs      []string           `json:"api_cidrs"` // who may call /mcp, /token, /register
	LoginCIDRs    []string           `json:"login_cidrs"`
	NetAllowCIDRs []string           `json:"net_allow_cidrs"` // destinations the net_* tools may reach (any port)    // who may open /authorize
	RedirectAllow []string           `json:"redirect_allow"`  // exact redirect URIs accepted at registration
	AllowLoopback bool               `json:"allow_loopback"`  // accept http://localhost|127.0.0.1:any/callback
	Hosts         map[string]HostCfg `json:"hosts"`
	DevInsecure   bool               `json:"dev_insecure"` // plain HTTP; only honoured when MCPGW_DEV=1
	TmpMaxAgeDays int                `json:"tmp_max_age_days"`

	// Remote-login hardening: sources outside trusted_cidrs need TOTP + Cloudflare Turnstile.
	TrustedCIDRs        []string `json:"trusted_cidrs"`
	TrustedSkipTOTP     *bool    `json:"trusted_skip_totp"`   // default true
	RemoteRequireTOTP   *bool    `json:"remote_require_totp"` // default true; false = remote logins need only passphrase + CAPTCHA
	TurnstileSiteKey    string   `json:"turnstile_sitekey"`
	TurnstileSecretFile string   `json:"turnstile_secret_file"`
	TurnstileHostnames  []string `json:"turnstile_hostnames"` // default: host of public_url
	TurnstileVerifyURL  string   `json:"turnstile_verify_url"`
}

func (c *Config) trustedSkipTOTP() bool   { return c.TrustedSkipTOTP == nil || *c.TrustedSkipTOTP }
func (c *Config) remoteRequireTOTP() bool { return c.RemoteRequireTOTP == nil || *c.RemoteRequireTOTP }

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
	if c.KBDB == "" {
		c.KBDB = "/var/lib/mcpgw/kb.db"
	}
	if c.BackupDir == "" {
		c.BackupDir = "/srv/mcp/backup"
	}
	if c.TmpMaxAgeDays == 0 {
		c.TmpMaxAgeDays = 14
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	c.LoginURL = strings.TrimRight(c.LoginURL, "/")
	if c.LoginURL == "" {
		c.LoginURL = c.PublicURL
	}
	if !strings.HasPrefix(c.LoginURL, "https://") && !(c.DevInsecure && os.Getenv("MCPGW_DEV") == "1") {
		return nil, errors.New("config: login_url must be https://")
	}
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
	cfg         *Config
	auth        *AuthFile
	st          *Store
	audit       *Auditor
	fsys        *FS
	lim         *Limiter
	certs       *certCache
	apiNets     []*net.IPNet
	loginNets   []*net.IPNet
	netNets     []*net.IPNet
	trustedNets []*net.IPNet
	ts          *Turnstile
	ipl         *ipLimiter
	vsem        chan struct{} // bounds concurrent passphrase hashing
	denyLog     sync.Map      // ip -> last deny log time
	hostLocks   sync.Map      // host -> *sync.Mutex (serialises write-mode operations)
	started     time.Time
	sess        *uiSessions
	bmu         sync.Mutex
	berr        string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		os.Exit(runSetup(os.Args[2:]))
	}
	if len(os.Args) > 1 && (os.Args[1] == "totp-enable" || os.Args[1] == "totp-disable") {
		os.Exit(runTOTP(os.Args[1] == "totp-enable", os.Args[2:]))
	}
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "kb-") {
		os.Exit(runKBCmd(os.Args[1], os.Args[2:]))
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
	if app.netNets, err = parseCIDRs(cfg.NetAllowCIDRs); err != nil {
		log.Fatal(err)
	}
	if app.trustedNets, err = parseCIDRs(cfg.TrustedCIDRs); err != nil {
		log.Fatal(err)
	}
	if app.ts, err = newTurnstile(cfg); err != nil {
		log.Fatalf("turnstile: %v", err)
	}
	app.ipl = newIPLimiter()
	app.vsem = make(chan struct{}, 4)
	if app.auth, err = loadAuth(cfg.AuthFile); err != nil {
		log.Fatalf("auth file: %v (run: mcpgw setup)", err)
	}
	if app.st, err = openStore(cfg.StateFile); err != nil {
		log.Fatal(err)
	}
	if app.audit, err = openAudit(cfg.AuditLog); err != nil {
		log.Fatal(err)
	}
	kb, err := openKBStore(cfg.KBDB)
	if err != nil {
		log.Fatal(err)
	}
	defer kb.Close()
	if kb.metaGet("legacy_imported") == "" { // one-time import of plain files from the previous file-based store
		n, v, sk, ierr := kb.importDir(cfg.KBDir, false)
		log.Printf("legacy import from %s: %d notes, %d versions, %d skipped (err=%v)", cfg.KBDir, n, v, sk, ierr)
		if ierr == nil {
			_ = kb.metaSet("legacy_imported", nowStr())
		}
	}
	if app.fsys, err = openFS(kb, cfg.TmpDir); err != nil {
		log.Fatal(err)
	}
	app.sess = newUISessions()
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
	log.Printf("mcpgw %s listening on %s (public %s); remote login: %v", version, cfg.Listen, cfg.PublicURL, app.remoteReady())
	ln, lerr := net.Listen("tcp", cfg.Listen)
	if lerr != nil {
		log.Fatal(lerr)
	}
	ln = newLimitListener(ln, 20, 200)
	if cfg.DevInsecure && os.Getenv("MCPGW_DEV") == "1" {
		log.Print("WARNING: dev mode, plain HTTP")
		err = srv.Serve(ln)
	} else {
		err = srv.ServeTLS(ln, "", "")
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
		a.ipl.gc()
		a.fsys.cleanTmp(time.Duration(a.cfg.TmpMaxAgeDays) * 24 * time.Hour)
		a.fsys.kb.pruneTrash()
		if backupDue(a.cfg.BackupDir, 24*time.Hour) {
			if _, err := a.runBackup("scheduled"); err != nil {
				log.Printf("scheduled backup failed: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runBackup makes a verified snapshot plus a readable export; the outcome is audited and remembered for the UI.
func (a *App) runBackup(reason string) (BackupInfo, error) {
	a.bmu.Lock()
	defer a.bmu.Unlock()
	bi, err := a.fsys.kb.backup(a.cfg.BackupDir)
	notes := 0
	if err == nil {
		notes, err = a.fsys.kb.refreshExport(a.cfg.BackupDir)
	}
	ev := map[string]any{"ev": "backup", "reason": reason, "ok": err == nil, "name": bi.Name, "bytes": bi.Size, "export_notes": notes}
	if err != nil {
		ev["error"] = err.Error()
		a.berr = time.Now().UTC().Format(time.RFC3339) + " " + err.Error()
	} else {
		a.berr = ""
	}
	a.audit.log(ev)
	return bi, err
}

func (a *App) lastBackupErr() string {
	a.bmu.Lock()
	defer a.bmu.Unlock()
	return a.berr
}

// runKBCmd implements the offline maintenance commands:
//
//	mcpgw kb-backup  [-config f]                 make a snapshot now
//	mcpgw kb-list    [-config f]                 list snapshots
//	mcpgw kb-restore [-config f] -file snap.db -yes   replace the database (stop the service first)
//	mcpgw kb-export  [-config f] -dir d          write all notes as plain files
//	mcpgw kb-import  [-config f] -dir d [-force] load plain files into the database
func runKBCmd(cmd string, args []string) int {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/mcpgw/config.json", "config file")
	file := fs.String("file", "", "snapshot file (kb-restore)")
	dir := fs.String("dir", "", "directory (kb-export, kb-import)")
	force := fs.Bool("force", false, "overwrite existing notes (kb-import)")
	yes := fs.Bool("yes", false, "confirm (kb-restore)")
	_ = fs.Parse(args)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cmd == "kb-list" {
		for _, b := range listSnapshots(cfg.BackupDir) {
			fmt.Printf("%s\t%s\t%d bytes\t%s\n", b.Name, b.Time, b.Size, b.SHA256)
		}
		return 0
	}
	if cmd == "kb-restore" {
		if *file == "" || !*yes {
			fmt.Fprintln(os.Stderr, "usage: mcpgw kb-restore -file <snapshot.db> -yes   (stop mcpgw.service first, start it afterwards)")
			return 2
		}
		if err := restoreSnapshot(cfg.KBDB, *file); err != nil {
			fmt.Fprintln(os.Stderr, "restore failed:", err)
			return 1
		}
		fmt.Println("restored; now start the service")
		return 0
	}
	kb, err := openKBStore(cfg.KBDB)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer kb.Close()
	switch cmd {
	case "kb-backup":
		bi, err := kb.backup(cfg.BackupDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		n, err := kb.refreshExport(cfg.BackupDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "export:", err)
			return 1
		}
		fmt.Printf("snapshot %s (%d bytes, sha256 %s); readable export: %d notes\n", bi.Name, bi.Size, bi.SHA256, n)
	case "kb-export":
		if *dir == "" {
			fmt.Fprintln(os.Stderr, "-dir is required")
			return 2
		}
		n, err := kb.exportDir(*dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("exported %d notes to %s\n", n, *dir)
	case "kb-import":
		if *dir == "" {
			fmt.Fprintln(os.Stderr, "-dir is required")
			return 2
		}
		n, v, sk, err := kb.importDir(*dir, *force)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("imported %d notes, %d versions, skipped %d\n", n, v, sk)
	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		return 2
	}
	return 0
}
