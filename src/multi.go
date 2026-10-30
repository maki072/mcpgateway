package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ---- host groups and multi-host calls ----

const (
	maxMultiHosts   = 40
	multiConcurrent = 6
)

// resolveHosts expands aliases, "@group" and (read mode only) "*" into a de-duplicated, ordered host list.
func (a *App) resolveHosts(list []string, write bool) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	names := make([]string, 0, len(a.cfg.Hosts))
	for n := range a.cfg.Hosts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, e := range list {
		e = strings.TrimSpace(e)
		switch {
		case e == "":
			continue
		case e == "*":
			if write {
				return nil, errors.New(`"*" is not allowed in write mode: name the hosts or a group (@group)`)
			}
			for _, n := range names {
				add(n)
			}
		case strings.HasPrefix(e, "@"):
			g, n := e[1:], 0
			for _, h := range names {
				if a.cfg.Hosts[h].Group == g {
					add(h)
					n++
				}
			}
			if n == 0 {
				return nil, fmt.Errorf("unknown or empty group %q (groups are set in the config: hosts.<alias>.group)", g)
			}
		default:
			if _, err := a.host(e); err != nil {
				return nil, err
			}
			add(e)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("hosts is empty")
	}
	if len(out) > maxMultiHosts {
		return nil, fmt.Errorf("at most %d hosts per call", maxMultiHosts)
	}
	return out, nil
}

type hostResult struct {
	host, text string
	failed     bool
}

func resultFailed(text string) bool {
	if strings.HasPrefix(text, "error:") {
		return true
	}
	first := strings.SplitN(text, "\n", 2)[0]
	if strings.HasPrefix(first, "exit ") {
		return strings.TrimSpace(strings.TrimPrefix(first, "exit ")) != "0"
	}
	return false
}

// foldResults groups hosts with identical output, so 22 equal answers cost one block.
func foldResults(rs []hostResult) string {
	order := []string{}
	groups := map[string][]string{}
	fails := 0
	for _, r := range rs {
		if _, ok := groups[r.text]; !ok {
			order = append(order, r.text)
		}
		groups[r.text] = append(groups[r.text], r.host)
		if r.failed {
			fails++
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d hosts: %d ok, %d failed", len(rs), len(rs)-fails, fails)
	for _, t := range order {
		hs := groups[t]
		if len(order) == 1 {
			fmt.Fprintf(&sb, "\n### same result on all %d hosts: %s\n%s", len(hs), strings.Join(hs, ", "), t)
			continue
		}
		fmt.Fprintf(&sb, "\n### %s (%d)\n%s", strings.Join(hs, ", "), len(hs), t)
	}
	s := sb.String()
	if len(s) > maxOutBytes {
		s = strings.ToValidUTF8(s[:maxOutBytes], "") + "\n[multi-host output cut at 64 KiB: narrow with grep/head/tail]"
	}
	return s
}

// sshMulti runs one command (or batch) on several hosts in parallel and folds identical results.
func (a *App) sshMulti(ctx context.Context, x execArgs) (string, error) {
	if x.Host != "" {
		return "", errors.New("use either host or hosts, not both")
	}
	if x.Background {
		return "", errors.New("background is for a single host")
	}
	write := x.Mode == "write"
	hs, err := a.resolveHosts(x.Hosts, write)
	if err != nil {
		return "", err
	}
	explicitNode := x.LogNode
	x.Hosts, x.LogNode = nil, ""
	if x.MaxBytes <= 0 {
		x.MaxBytes = defOutBytes / 2
	}
	out := make([]hostResult, len(hs))
	sem := make(chan struct{}, multiConcurrent)
	var wg sync.WaitGroup
	for i, h := range hs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			y := x
			y.Host = h
			r, e := a.sshRun(ctx, y)
			if e != nil {
				out[i] = hostResult{h, "error: " + e.Error(), true}
				return
			}
			out[i] = hostResult{h, r, resultFailed(r)}
		}(i, h)
	}
	wg.Wait()
	res := foldResults(out)
	if write {
		res += a.logMulti(out, explicitNode, x)
	}
	return res, nil
}

// logMulti writes one kb log entry per node (explicit log_node or the hosts' configured default).
func (a *App) logMulti(rs []hostResult, explicit string, x execArgs) string {
	byNode := map[string][]hostResult{}
	var nodes []string
	for _, r := range rs {
		n := explicit
		if n == "" {
			n = a.cfg.Hosts[r.host].LogNode
		}
		if n == "" {
			continue
		}
		if _, ok := byNode[n]; !ok {
			nodes = append(nodes, n)
		}
		byNode[n] = append(byNode[n], r)
	}
	var sb strings.Builder
	for _, n := range nodes {
		var names []string
		fails := 0
		for _, r := range byNode[n] {
			names = append(names, r.host)
			if r.failed {
				fails++
			}
		}
		cmd := x.Command
		if len(x.Commands) > 0 {
			cmd = strings.Join(x.Commands, " ;; ")
		}
		entry := fmt.Sprintf("ssh %s (write, %d ok / %d failed): %s. Backup/rollback: %s. Command: %s",
			strings.Join(names, ","), len(names)-fails, fails, x.Reason, x.BackupNote, clip(maskSecrets(cmd), 400))
		if msg, err := a.fsys.kbLog(n, entry); err != nil {
			sb.WriteString("\n[kb log failed for " + n + ": " + err.Error() + "]")
		} else {
			sb.WriteString("\n[" + msg + "]")
		}
	}
	return sb.String()
}

// scpMulti uploads one tmp file to several hosts in parallel.
func (a *App) scpMulti(ctx context.Context, x xferArgs) (string, error) {
	if x.Host != "" {
		return "", errors.New("use either host or hosts, not both")
	}
	hs, err := a.resolveHosts(x.Hosts, true)
	if err != nil {
		return "", err
	}
	x.Hosts = nil
	out := make([]hostResult, len(hs))
	sem := make(chan struct{}, multiConcurrent)
	var wg sync.WaitGroup
	for i, h := range hs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			y := x
			y.Host = h
			r, e := a.scp(ctx, y, true)
			if e != nil {
				out[i] = hostResult{h, "error: " + e.Error(), true}
				return
			}
			// the text differs per host only by its name: fold on the common part
			out[i] = hostResult{h, strings.Replace(r, h+":", "<host>:", 1), false}
		}(i, h)
	}
	wg.Wait()
	return foldResults(out), nil
}

// ---- change window: reason and backup note once, then window=<id> on the write calls ----

type chgWindow struct {
	ID, Reason, Backup string
	Hosts              map[string]bool // empty: any host
	Exp                time.Time
}

var windows = struct {
	sync.Mutex
	m map[string]*chgWindow
}{m: map[string]*chgWindow{}}

const (
	defWindowMin = 30
	maxWindowMin = 120
)

func (a *App) openWindow(reason, backup string, hosts []string, minutes int) (string, error) {
	if err := checkWrite(reason, backup); err != nil {
		return "", err
	}
	if minutes <= 0 {
		minutes = defWindowMin
	}
	if minutes > maxWindowMin {
		minutes = maxWindowMin
	}
	w := &chgWindow{ID: "w-" + randToken(4), Reason: strings.TrimSpace(reason), Backup: strings.TrimSpace(backup), Hosts: map[string]bool{}, Exp: time.Now().Add(time.Duration(minutes) * time.Minute)}
	scope := "any host"
	if len(hosts) > 0 {
		hs, err := a.resolveHosts(hosts, true)
		if err != nil {
			return "", err
		}
		for _, h := range hs {
			w.Hosts[h] = true
		}
		scope = strings.Join(hs, ",")
	}
	windows.Lock()
	defer windows.Unlock()
	for id, o := range windows.m {
		if time.Now().After(o.Exp) {
			delete(windows.m, id)
		}
	}
	if len(windows.m) >= 8 {
		return "", errors.New("too many open change windows: close one with ssh op=window id=<id> close=true")
	}
	windows.m[w.ID] = w
	return fmt.Sprintf("window %s open until %s UTC (%d min), scope: %s. Use window=%s instead of reason/backup_note on write calls; disruptive commands still need allow_disruptive.",
		w.ID, w.Exp.UTC().Format("15:04"), minutes, scope, w.ID), nil
}

func closeWindow(id string) (string, error) {
	windows.Lock()
	defer windows.Unlock()
	if _, ok := windows.m[id]; !ok {
		return "", errors.New("unknown or expired window id")
	}
	delete(windows.m, id)
	return "window " + id + " closed", nil
}

// windowFill takes reason/backup_note from an open window (explicit values win) and checks the host scope.
func (a *App) windowFill(id string, entries []string, reason, backup *string) error {
	windows.Lock()
	w := windows.m[id]
	windows.Unlock()
	if w == nil || time.Now().After(w.Exp) {
		return errors.New("window unknown or expired: open a new one with ssh op=window")
	}
	if len(w.Hosts) > 0 {
		hs, err := a.resolveHosts(entries, true)
		if err != nil {
			return err
		}
		for _, h := range hs {
			if !w.Hosts[h] {
				return fmt.Errorf("host %s is outside the scope of window %s", h, id)
			}
		}
	}
	if strings.TrimSpace(*reason) == "" {
		*reason = w.Reason
	}
	if strings.TrimSpace(*backup) == "" {
		*backup = w.Backup
	}
	return nil
}

// ---- usage statistics from the audit log ----

type usageAgg struct{ calls, fails, out, in int }

func (a *App) usageReport(sinceStr string, top int) (string, error) {
	if sinceStr == "" {
		sinceStr = "24h"
	}
	if top <= 0 {
		top = 10
	}
	if top > 40 {
		top = 40
	}
	since, err := parseSince(sinceStr)
	if err != nil {
		return "", err
	}
	f, err := os.Open(a.cfg.AuditLog)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > 16<<20 {
		_, _ = f.Seek(-(16 << 20), 2)
	}
	byTool, byHost := map[string]*usageAgg{}, map[string]*usageAgg{}
	type heavy struct {
		ts, key, host, cmd string
		out                int
	}
	var heavies []heavy
	total := usageAgg{}
	add := func(m map[string]*usageAgg, k string, ok bool, out, in int) {
		g := m[k]
		if g == nil {
			g = &usageAgg{}
			m[k] = g
		}
		g.calls++
		g.out += out
		g.in += in
		if !ok {
			g.fails++
		}
	}
	num := func(e map[string]any, k string) int { v, _ := e[k].(float64); return int(v) }
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	first := ""
	for sc.Scan() {
		var e map[string]any
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		gs := func(k string) string { v, _ := e[k].(string); return v }
		if gs("ev") != "tool" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, gs("ts")); err == nil {
			if t.Before(since) {
				continue
			}
			if first == "" {
				first = gs("ts")
			}
		}
		key := gs("tool")
		if op := gs("op"); op != "" {
			key += "/" + op
		}
		ok, _ := e["ok"].(bool)
		out, in := num(e, "out_bytes"), num(e, "in_bytes")
		add(byTool, key, ok, out, in)
		if h := gs("host"); h != "" {
			add(byHost, h, ok, out, in)
		}
		total.calls++
		total.out += out
		total.in += in
		cmd := gs("command")
		if cmd == "" {
			cmd = gs("path")
		}
		if cmd == "" {
			cmd = gs("query")
		}
		heavies = append(heavies, heavy{gs("ts"), key, gs("host"), clip(strings.Join(strings.Fields(cmd), " "), 80), out})
	}
	if total.calls == 0 {
		return "no tool calls in the period", nil
	}
	table := func(title string, m map[string]*usageAgg) string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if m[keys[i]].out != m[keys[j]].out {
				return m[keys[i]].out > m[keys[j]].out
			}
			return keys[i] < keys[j]
		})
		if len(keys) > top {
			keys = keys[:top]
		}
		var sb strings.Builder
		sb.WriteString(title + " (calls, out KiB, in KiB, fails):\n")
		for _, k := range keys {
			g := m[k]
			fmt.Fprintf(&sb, "  %-26s %5d %8.1f %7.1f %4d\n", k, g.calls, float64(g.out)/1024, float64(g.in)/1024, g.fails)
		}
		return sb.String()
	}
	sort.Slice(heavies, func(i, j int) bool { return heavies[i].out > heavies[j].out })
	if len(heavies) > 5 {
		heavies = heavies[:5]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "tool calls since %s: %d, out %.1f KiB, in %.1f KiB (in_bytes is recorded since v0.2.3)\n", sinceStr, total.calls, float64(total.out)/1024, float64(total.in)/1024)
	sb.WriteString(table("by tool/op", byTool))
	sb.WriteString(table("by host", byHost))
	sb.WriteString("largest single answers:\n")
	for _, h := range heavies {
		ts := h.ts
		if len(ts) >= 16 {
			ts = ts[5:16]
		}
		fmt.Fprintf(&sb, "  %s %-22s %-10s %7d B  %s\n", ts, h.key, h.host, h.out, h.cmd)
	}
	return sb.String(), nil
}

// ---- file intake from the owner's network (one-time URL) ----

type upSlot struct {
	Name string
	Exp  time.Time
	Max  int64
}

var uploads = struct {
	sync.Mutex
	m map[string]*upSlot
}{m: map[string]*upSlot{}}

const (
	defUploadMB = 64
	maxUploadMB = 256
	uploadTTL   = 10 * time.Minute
)

func (a *App) newUpload(name string, maxMB int) (string, error) {
	rel, err := cleanRel(name)
	if err != nil || rel == "." || strings.HasSuffix(name, "/") {
		return "", errors.New("name: a relative file path under the tmp root, e.g. incoming/app.tgz")
	}
	if maxMB <= 0 {
		maxMB = defUploadMB
	}
	if maxMB > maxUploadMB {
		maxMB = maxUploadMB
	}
	tok := randToken(16)
	uploads.Lock()
	defer uploads.Unlock()
	for k, s := range uploads.m {
		if time.Now().After(s.Exp) {
			delete(uploads.m, k)
		}
	}
	if len(uploads.m) >= 8 {
		return "", errors.New("too many open upload links; use or wait for them to expire (10 min)")
	}
	uploads.m[tok] = &upSlot{Name: rel, Exp: time.Now().Add(uploadTTL), Max: int64(maxMB) << 20}
	base := a.cfg.LoginURL
	if base == "" {
		base = a.cfg.PublicURL
	}
	return fmt.Sprintf("PUT the file within 10 minutes (single use, max %d MiB, trusted network only) to:\n%s/up/%s\nWindows: curl.exe -sS -T <file> <url>. It lands in tmp:%s; then use tmp_path=%s with ssh upload or fs import.", maxMB, strings.TrimRight(base, "/"), tok, rel, rel), nil
}

func (a *App) uploadPut(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !a.isTrusted(ip) {
		a.audit.log(map[string]any{"ev": "upload_denied", "ip": ip.String()})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "use PUT", http.StatusMethodNotAllowed)
		return
	}
	tok := strings.TrimPrefix(r.URL.Path, "/up/")
	uploads.Lock()
	s := uploads.m[tok]
	delete(uploads.m, tok) // single use, also when the transfer fails
	uploads.Unlock()
	if s == nil || time.Now().After(s.Exp) {
		http.Error(w, "unknown or expired link", http.StatusNotFound)
		return
	}
	root, err := a.fsys.root("tmp")
	if err != nil {
		http.Error(w, "tmp root unavailable", http.StatusInternalServerError)
		return
	}
	if err := mkdirAll(root, path.Dir(s.Name)); err != nil {
		http.Error(w, "cannot create directory", http.StatusInternalServerError)
		return
	}
	f, err := root.OpenFile(s.Name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		http.Error(w, "cannot create file", http.StatusInternalServerError)
		return
	}
	h := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(f, h), http.MaxBytesReader(w, r.Body, s.Max))
	if e := f.Close(); cerr == nil {
		cerr = e
	}
	if cerr != nil {
		_ = root.Remove(s.Name)
		a.audit.log(map[string]any{"ev": "upload", "ip": ip.String(), "path": s.Name, "ok": false, "error": cerr.Error()})
		http.Error(w, "upload failed: "+cerr.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	a.audit.log(map[string]any{"ev": "upload", "ip": ip.String(), "path": s.Name, "ok": true, "bytes": n, "sha256": sum})
	fmt.Fprintf(w, "stored tmp:%s %d bytes sha256 %s\n", s.Name, n, sum)
}

// ---- import of a .tgz (from tmp) into the knowledge base ----

const (
	maxImportFiles = 500
	maxImportBytes = 32 << 20
)

func (a *App) importArchive(tmpPath, prefix string, overwrite, redact bool) (string, error) {
	local, err := a.fsys.tmpLocalPath(tmpPath)
	if err != nil {
		return "", err
	}
	fh, err := os.Open(local)
	if err != nil {
		return "", errors.New("tmp_path does not exist")
	}
	defer fh.Close()
	var rd io.Reader = fh
	br := bufio.NewReader(fh)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return "", err
		}
		defer gz.Close()
		rd = gz
	} else {
		rd = br
	}
	pre := ""
	if prefix != "" {
		if pre, err = cleanRel(prefix); err != nil || pre == "." {
			return "", errors.New("prefix: a relative kb directory")
		}
	}
	tr := tar.NewReader(rd)
	var done, existing, unsuitable, secret int
	var names, notes []string
	var total int64
	for {
		hd, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("archive: %v", err)
		}
		if hd.Typeflag != tar.TypeReg {
			continue
		}
		if done+existing+unsuitable+secret >= maxImportFiles {
			return "", fmt.Errorf("more than %d files in the archive", maxImportFiles)
		}
		rel, err := cleanRel(strings.TrimPrefix(hd.Name, "./"))
		if err != nil || rel == "." || strings.HasPrefix(path.Base(rel), ".") || strings.HasPrefix(rel, ".") || reserved(rel) || hd.Size > maxRead {
			unsuitable++
			continue
		}
		if pre != "" {
			rel = path.Join(pre, rel)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxRead+1))
		if err != nil || len(b) > maxRead || !utf8.Valid(b) || strings.IndexByte(string(b), 0) >= 0 {
			unsuitable++
			continue
		}
		total += int64(len(b))
		if total > maxImportBytes {
			return "", errors.New("archive content exceeds 32 MiB")
		}
		text := string(b)
		if m := maskSecrets(text); m != text {
			if !redact {
				secret++
				notes = append(notes, "looks like it holds secrets, skipped (redact=true masks them): "+rel)
				continue
			}
			text = m
		}
		if _, _, rerr := a.fsys.read("kb", rel, 0, 1); rerr == nil && !overwrite {
			existing++
			continue
		}
		if _, err := a.fsys.write("kb", rel, text, "overwrite"); err != nil {
			unsuitable++
			notes = append(notes, rel+": "+err.Error())
			continue
		}
		done++
		if len(names) < 25 {
			names = append(names, rel)
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "imported %d notes (previous versions stay in kb history); skipped: %d existing (overwrite=true replaces), %d unsuitable, %d with secrets", done, existing, unsuitable, secret)
	for _, n := range names {
		sb.WriteString("\n  + " + n)
	}
	for i, n := range notes {
		if i >= 10 {
			sb.WriteString("\n  ...")
			break
		}
		sb.WriteString("\n  ! " + n)
	}
	return sb.String(), nil
}

func atoiDefault(s string, d int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return d
}
