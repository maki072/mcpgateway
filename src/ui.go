package main

import (
	"bufio"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Web management UI: reachable only from login_cidrs, own session cookie + CSRF header,
// all content is rendered client-side with textContent (no HTML from stored notes is ever interpreted).

//go:embed ui.html
var uiHTML string

const (
	uiIdle       = 30 * time.Minute
	uiMax        = 8 * time.Hour
	uiIdleRemote = 15 * time.Minute // sessions of non-trusted sources are shorter and bound to the client address
	uiMaxRemote  = 4 * time.Hour
)

type uiSession struct {
	csrf    string
	created time.Time
	last    time.Time
	ipk     string // client key for remote sessions, "" for trusted ones
}

func (ss *uiSession) expired(now time.Time) bool {
	idle, max := uiIdle, uiMax
	if ss.ipk != "" {
		idle, max = uiIdleRemote, uiMaxRemote
	}
	return now.Sub(ss.last) > idle || now.Sub(ss.created) > max
}

type uiSessions struct {
	mu sync.Mutex
	m  map[string]*uiSession
}

func newUISessions() *uiSessions { return &uiSessions{m: map[string]*uiSession{}} }

func (s *uiSessions) create(ipk string) (string, *uiSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if v.expired(now) {
			delete(s.m, k)
		}
	}
	if len(s.m) >= 5 { // a single operator: drop everything older rather than grow
		s.m = map[string]*uiSession{}
	}
	tok := randToken(32)
	ss := &uiSession{csrf: randToken(24), created: now, last: now, ipk: ipk}
	s.m[sha(tok)] = ss
	return tok, ss
}

func (s *uiSessions) get(tok, ipk string) *uiSession {
	if tok == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.m[sha(tok)]
	if ss == nil {
		return nil
	}
	now := time.Now()
	if ss.expired(now) || (ss.ipk != "" && ss.ipk != ipk) {
		delete(s.m, sha(tok))
		return nil
	}
	ss.last = now
	return ss
}

func (s *uiSessions) drop(tok string) {
	s.mu.Lock()
	delete(s.m, sha(tok))
	s.mu.Unlock()
}

const uiCookie = "mcpgw_ui"

func (a *App) uiRoutes(m *http.ServeMux) {
	g := func(h http.HandlerFunc) http.HandlerFunc { return a.gate(a.loginNets, h) }
	m.HandleFunc("/ui", g(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ui/", http.StatusFound) }))
	m.HandleFunc("/ui/", g(a.uiPage))
	m.HandleFunc("/ui/api/session", g(a.uiSessionInfo))
	m.HandleFunc("/ui/api/login", g(a.uiLogin))
	m.HandleFunc("/ui/api/logout", g(a.uiAuth(a.uiLogout)))
	m.HandleFunc("/ui/api/list", g(a.uiAuth(a.uiList)))
	m.HandleFunc("/ui/api/file", g(a.uiAuth(a.uiFile)))
	m.HandleFunc("/ui/api/move", g(a.uiAuth(a.uiMove)))
	m.HandleFunc("/ui/api/mkdir", g(a.uiAuth(a.uiMkdir)))
	m.HandleFunc("/ui/api/versions", g(a.uiAuth(a.uiVersions)))
	m.HandleFunc("/ui/api/version", g(a.uiAuth(a.uiVersion)))
	m.HandleFunc("/ui/api/restore", g(a.uiAuth(a.uiRestore)))
	m.HandleFunc("/ui/api/backups", g(a.uiAuth(a.uiBackups)))
	m.HandleFunc("/ui/api/search", g(a.uiAuth(a.uiSearch)))
	m.HandleFunc("/ui/api/index", g(a.uiAuth(a.uiIndex)))
	m.HandleFunc("/ui/api/stats", g(a.uiAuth(a.uiStats)))
	m.HandleFunc("/ui/api/audit", g(a.uiAuth(a.uiAudit)))
}

func jerr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (a *App) uiPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui/" {
		http.NotFound(w, r)
		return
	}
	nonce := randToken(16)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	csp := "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	if a.ts != nil && !a.isTrusted(clientIP(r)) { // the CAPTCHA widget needs its script, frame and verification call
		csp = "default-src 'none'; script-src 'nonce-" + nonce + "' https://challenges.cloudflare.com; style-src 'nonce-" + nonce + "'; " +
			"connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	}
	h.Set("Content-Security-Policy", csp)
	_, _ = io.WriteString(w, strings.ReplaceAll(uiHTML, "{{NONCE}}", nonce))
}

func (a *App) uiSessionFrom(r *http.Request) *uiSession {
	c, err := r.Cookie(uiCookie)
	if err != nil {
		return nil
	}
	return a.sess.get(c.Value, ipKey(clientIP(r)))
}

func (a *App) uiSessionInfo(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	out := map[string]any{"authed": false, "need_totp": a.needCode(ip), "remote": !a.isTrusted(ip)}
	if !a.isTrusted(ip) {
		out["remote_ready"] = a.remoteReady()
		if a.ts != nil {
			out["sitekey"] = a.ts.siteKey
		}
	}
	if s := a.uiSessionFrom(r); s != nil {
		out["authed"], out["csrf"] = true, s.csrf
	}
	writeJSON(w, 200, out)
}

func sameOrigin(a *App, r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true // same-origin GETs may omit it; SameSite=Strict + CSRF header cover the rest
	}
	return o == a.cfg.LoginURL || o == a.cfg.PublicURL
}

func (a *App) uiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !sameOrigin(a, r) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		jerr(w, 400, "bad request")
		return
	}
	var x struct {
		Pass, TOTP string
		TS         string `json:"ts"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&x); err != nil {
		jerr(w, 400, "bad request")
		return
	}
	if st, msg := a.checkLogin(r.Context(), r, x.Pass, x.TOTP, x.TS, true); st != 0 {
		jerr(w, st, msg)
		return
	}
	ip := clientIP(r)
	ipk := ""
	if !a.isTrusted(ip) {
		ipk = ipKey(ip)
	}
	tok, ss := a.sess.create(ipk)
	http.SetCookie(w, &http.Cookie{Name: uiCookie, Value: tok, Path: "/ui/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int((map[bool]time.Duration{true: uiMaxRemote, false: uiMax})[ipk != ""].Seconds())})
	writeJSON(w, 200, map[string]any{"authed": true, "csrf": ss.csrf})
}

// uiAuth requires a valid session; state-changing methods also need the CSRF header and a JSON content type.
func (a *App) uiAuth(h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := a.uiSessionFrom(r)
		if s == nil {
			jerr(w, 401, "not logged in")
			return
		}
		if r.Method != http.MethodGet {
			if !sameOrigin(a, r) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF")), []byte(s.csrf)) != 1 {
				a.audit.log(map[string]any{"ev": "ui_csrf_reject", "ip": clientIP(r).String(), "path": r.URL.Path})
				jerr(w, 403, "csrf check failed")
				return
			}
			if r.ContentLength != 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				jerr(w, 415, "json required")
				return
			}
		}
		h(w, r)
	}
}

func (a *App) uiLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(uiCookie); err == nil {
		a.sess.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: uiCookie, Value: "", Path: "/ui/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) uiLog(r *http.Request, op string, f map[string]any) {
	f["ev"], f["op"], f["ip"] = "ui", op, clientIP(r).String()
	a.audit.log(f)
}

func (a *App) uiList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hidden := q.Get("hidden") == "1"
	es, err := a.fsys.list(q.Get("root"), q.Get("path"), 1, hidden)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	if es == nil {
		es = []listEntry{}
	}
	writeJSON(w, 200, es)
}

func (f *FS) stat(root, rel string) (*fileStat, error) {
	if c, ok, err := f.kbRel(root, rel); ok {
		if err != nil {
			return nil, err
		}
		return f.kb.stat(c)
	}
	r, err := f.root(root)
	if err != nil {
		return nil, err
	}
	if rel, err = cleanRel(rel); err != nil {
		return nil, err
	}
	st, err := r.Stat(rel)
	if err != nil {
		return nil, err
	}
	return &fileStat{st.Size(), st.ModTime(), st.IsDir()}, nil
}

func (a *App) uiFile(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		st, err := a.fsys.stat(q.Get("root"), q.Get("path"))
		if err != nil {
			jerr(w, 404, "not found")
			return
		}
		s, more, err := a.fsys.read(q.Get("root"), q.Get("path"), 0, maxRead)
		if err != nil {
			jerr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"content": s, "truncated": more, "size": st.Size(), "mtime": st.ModTime().UTC().Format(time.RFC3339Nano)})
	case http.MethodPut:
		var x struct {
			Root, Path, Content, Mode string
			ExpectMTime               string `json:"expect_mtime"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWrite+(64<<10))).Decode(&x); err != nil {
			jerr(w, 400, "bad request")
			return
		}
		if x.Mode != "create" && x.Mode != "overwrite" {
			jerr(w, 400, "mode must be create or overwrite")
			return
		}
		if x.Mode == "overwrite" && x.ExpectMTime != "" {
			if st, err := a.fsys.stat(x.Root, x.Path); err == nil && st.ModTime().UTC().Format(time.RFC3339Nano) != x.ExpectMTime {
				jerr(w, 409, "file changed since you opened it (edited elsewhere); reload before saving")
				return
			}
		}
		msg, err := a.fsys.write(x.Root, x.Path, x.Content, x.Mode)
		a.uiLog(r, "write", map[string]any{"root": x.Root, "path": x.Path, "mode": x.Mode, "bytes": len(x.Content), "ok": err == nil})
		if err != nil {
			jerr(w, 400, err.Error())
			return
		}
		st, _ := a.fsys.stat(x.Root, x.Path)
		mt := ""
		if st != nil {
			mt = st.ModTime().UTC().Format(time.RFC3339Nano)
		}
		writeJSON(w, 200, map[string]any{"message": msg, "mtime": mt})
	case http.MethodDelete:
		q := r.URL.Query()
		msg, err := a.fsys.remove(q.Get("root"), q.Get("path"))
		a.uiLog(r, "delete", map[string]any{"root": q.Get("root"), "path": q.Get("path"), "ok": err == nil})
		if err != nil {
			jerr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"message": msg})
	default:
		jerr(w, 405, "method not allowed")
	}
}

func (a *App) uiMove(w http.ResponseWriter, r *http.Request) {
	var x struct{ Root, From, To string }
	if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&x) != nil {
		jerr(w, 400, "bad request")
		return
	}
	s, more, err := a.fsys.read(x.Root, x.From, 0, maxRead)
	if err == nil && more {
		err = errors.New("file too large to move here")
	}
	if err == nil {
		_, err = a.fsys.write(x.Root, x.To, s, "create")
	}
	if err == nil {
		_, err = a.fsys.remove(x.Root, x.From)
	}
	a.uiLog(r, "move", map[string]any{"root": x.Root, "from": x.From, "to": x.To, "ok": err == nil})
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) uiMkdir(w http.ResponseWriter, r *http.Request) {
	var x struct{ Root, Path string }
	if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&x) != nil {
		jerr(w, 400, "bad request")
		return
	}
	rel, err := cleanRel(x.Path)
	if err == nil && (rel == "." || reserved(rel)) {
		err = errors.New("invalid path")
	}
	if err == nil && x.Root == "kb" {
		err = a.fsys.kb.mkdir(rel)
	} else if err == nil {
		var root *os.Root
		if root, err = a.fsys.root(x.Root); err == nil {
			a.fsys.mu.Lock()
			err = mkdirAll(root, rel)
			a.fsys.mu.Unlock()
		}
	}
	a.uiLog(r, "mkdir", map[string]any{"root": x.Root, "path": x.Path, "ok": err == nil})
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

const tsLen = len("20060102T150405.000")

func (a *App) uiVersions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind := "history"
	if q.Get("kind") == "trash" {
		kind = "trash"
	}
	rel := ""
	if p := q.Get("path"); p != "" {
		c, err := cleanRel(p)
		if err != nil {
			jerr(w, 400, err.Error())
			return
		}
		rel = c
	}
	v, err := a.fsys.kb.versions(kind, rel, 100)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

func (a *App) uiVersion(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	p, kind, body, err := a.fsys.kb.versionBody(id)
	if err != nil {
		jerr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"path": p, "kind": kind, "content": body})
}

func (a *App) uiRestore(w http.ResponseWriter, r *http.Request) {
	var x struct{ ID int64 }
	if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&x) != nil {
		jerr(w, 400, "bad request")
		return
	}
	msg, err := a.fsys.kb.restore(x.ID)
	a.uiLog(r, "restore", map[string]any{"version": x.ID, "ok": err == nil})
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"message": msg})
}

func (a *App) uiBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		bi, err := a.runBackup("manual")
		a.uiLog(r, "backup_now", map[string]any{"ok": err == nil})
		if err != nil {
			jerr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, bi)
		return
	}
	l := listSnapshots(a.cfg.BackupDir)
	if l == nil {
		l = []BackupInfo{}
	}
	writeJSON(w, 200, map[string]any{"dir": a.cfg.BackupDir, "snapshots": l, "last_error": a.lastBackupErr()})
}

func (a *App) uiSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var tags []string
	if t := strings.TrimSpace(q.Get("tags")); t != "" {
		tags = splitTags(t)
	}
	lim, _ := strconv.Atoi(q.Get("limit"))
	s, err := a.fsys.kbFind(q.Get("q"), tags, q.Get("path"), q.Get("logs") == "1", lim)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"text": s})
}

func (a *App) uiIndex(w http.ResponseWriter, r *http.Request) {
	s, err := a.fsys.kbIndex(r.URL.Query().Get("path"), r.URL.Query().Get("logs") == "1", true)
	if err != nil {
		jerr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"text": s})
}

func (a *App) uiAudit(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if n <= 0 || n > 300 {
		n = 100
	}
	lines, err := tailLines(a.cfg.AuditLog, n)
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string][]string{"lines": lines})
}

func tailLines(p string, n int) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > 8<<20 {
		_, _ = f.Seek(-(8 << 20), io.SeekEnd)
	}
	var ring []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		ring = append(ring, sc.Text())
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	return ring, nil
}

// ---- statistics ----

type dirStat struct {
	Name  string `json:"name"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
}

type recentFile struct {
	Path  string `json:"path"`
	MTime string `json:"mtime"`
	Size  int64  `json:"size"`
}

func (f *FS) walkStats(root string) (files int, bytes int64, byDir map[string]*dirStat, recent []recentFile, hist, trash int, oldest time.Time, err error) {
	r, e := f.root(root)
	if e != nil {
		err = e
		return
	}
	byDir = map[string]*dirStat{}
	err = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return nil
		}
		info, ie := d.Info()
		if ie != nil {
			return nil
		}
		switch {
		case strings.HasPrefix(p, ".history/"):
			hist++
			return nil
		case strings.HasPrefix(p, ".trash/"):
			trash++
			return nil
		}
		files++
		bytes += info.Size()
		top := "(root)"
		if i := strings.Index(p, "/"); i > 0 {
			top = p[:i]
		}
		ds := byDir[top]
		if ds == nil {
			ds = &dirStat{Name: top}
			byDir[top] = ds
		}
		ds.Files++
		ds.Bytes += info.Size()
		recent = append(recent, recentFile{p, info.ModTime().UTC().Format(time.RFC3339), info.Size()})
		if oldest.IsZero() || info.ModTime().Before(oldest) {
			oldest = info.ModTime()
		}
		return nil
	})
	sort.Slice(recent, func(i, j int) bool { return recent[i].MTime > recent[j].MTime })
	if len(recent) > 10 {
		recent = recent[:10]
	}
	return
}

type dayStat struct {
	Day    string `json:"day"`
	Calls  int    `json:"calls"`
	Errors int    `json:"errors"`
	Logins int    `json:"login_fail"`
}

func (a *App) auditStats() map[string]any {
	lines, err := tailLines(a.cfg.AuditLog, 1<<30)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	tools, toolErr, evs := map[string]int{}, map[string]int{}, map[string]int{}
	days := map[string]*dayStat{}
	var last []map[string]any
	sshWrite := 0
	for _, ln := range lines {
		var e map[string]any
		if json.Unmarshal([]byte(ln), &e) != nil {
			continue
		}
		ev, _ := e["ev"].(string)
		ts, _ := e["ts"].(string)
		day := ""
		if len(ts) >= 10 {
			day = ts[:10]
		}
		ds := days[day]
		if ds == nil && day != "" {
			ds = &dayStat{Day: day}
			days[day] = ds
		}
		evs[ev]++
		switch ev {
		case "tool":
			t, _ := e["tool"].(string)
			ok, _ := e["ok"].(bool)
			tools[t]++
			if ds != nil {
				ds.Calls++
			}
			if !ok {
				toolErr[t]++
				if ds != nil {
					ds.Errors++
				}
			}
			if m, _ := e["mode"].(string); t == "ssh_exec" && m == "write" {
				sshWrite++
			}
			item := map[string]any{"ts": ts, "tool": t, "ok": ok}
			for _, k := range []string{"host", "path", "query", "node", "command"} {
				if v, ok := e[k].(string); ok && v != "" {
					item["target"] = clip(v, 120)
					break
				}
			}
			last = append(last, item)
			if len(last) > 15 {
				last = last[1:]
			}
		case "login_fail":
			if ds != nil {
				ds.Logins++
			}
		}
	}
	var dl []dayStat
	for _, d := range days {
		dl = append(dl, *d)
	}
	sort.Slice(dl, func(i, j int) bool { return dl[i].Day < dl[j].Day })
	if len(dl) > 14 {
		dl = dl[len(dl)-14:]
	}
	for i, j := 0, len(last)-1; i < j; i, j = i+1, j-1 {
		last[i], last[j] = last[j], last[i]
	}
	return map[string]any{"tools": tools, "tool_errors": toolErr, "events": evs, "days": dl, "last_tools": last, "ssh_write": sshWrite}
}

func (a *App) uiStats(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	ks, err := a.fsys.kb.stats()
	if err != nil {
		jerr(w, 500, err.Error())
		return
	}
	kbm := map[string]any{"files": ks.Files, "bytes": ks.Bytes, "dirs": ks.ByDir, "recent": ks.Recent, "history_files": ks.History, "trash_files": ks.Trash, "db_bytes": ks.DBBytes}
	if ks.Oldest != "" {
		kbm["oldest"] = ks.Oldest
	}
	out["kb"] = kbm
	{
		files, bytes, byDir, recent, _, _, oldest, err := a.fsys.walkStats("tmp")
		if err != nil {
			jerr(w, 500, err.Error())
			return
		}
		dirs := []*dirStat{}
		for _, d := range byDir {
			dirs = append(dirs, d)
		}
		sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
		m := map[string]any{"files": files, "bytes": bytes, "dirs": dirs, "recent": recent}
		if !oldest.IsZero() {
			m["oldest"] = oldest.UTC().Format(time.RFC3339)
		}
		out["tmp"] = m
	}
	docs, _ := a.fsys.loadKB(".", true)
	tagCount := map[string]int{}
	notes := 0
	for _, d := range docs {
		if !strings.Contains(d.Path, "/log/") {
			notes++
		}
		for _, t := range d.Tags {
			tagCount[t]++
		}
	}
	type tc struct {
		Tag string `json:"tag"`
		N   int    `json:"n"`
	}
	var tl []tc
	for t, n := range tagCount {
		tl = append(tl, tc{t, n})
	}
	sort.Slice(tl, func(i, j int) bool {
		if tl[i].N != tl[j].N {
			return tl[i].N > tl[j].N
		}
		return tl[i].Tag < tl[j].Tag
	})
	if len(tl) > 20 {
		tl = tl[:20]
	}
	out["notes"], out["tags"] = notes, tl
	srv := map[string]any{"version": version, "uptime_sec": int(time.Since(a.started).Seconds()), "hosts": len(a.cfg.Hosts)}
	if t, err := a.certs.notAfter(); err == nil {
		srv["cert_expires"] = t.UTC().Format("2006-01-02")
		srv["cert_days_left"] = int(time.Until(t).Hours() / 24)
	}
	a.st.mu.Lock()
	srv["oauth_clients"], srv["oauth_tokens"] = len(a.st.Clients), len(a.st.Tokens)
	a.st.mu.Unlock()
	var sf syscall.Statfs_t
	if syscall.Statfs(filepath.Dir(a.cfg.KBDB), &sf) == nil {
		srv["disk_free_bytes"] = int64(sf.Bavail) * int64(sf.Bsize)
		srv["disk_total_bytes"] = int64(sf.Blocks) * int64(sf.Bsize)
	}
	out["server"] = srv
	out["audit"] = a.auditStats()
	writeJSON(w, 200, out)
}
