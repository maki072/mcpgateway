package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite (no CGO)
)

// KBStore keeps the knowledge base in one SQLite file (WAL mode):
// nodes = current notes, versions = history (previous contents) and trash (deleted notes),
// fts = FTS5 index maintained by triggers. The file is the single source of truth.

const (
	histKeepDB  = 20
	trashKeep   = 2000
	trashMaxAge = 90 * 24 * time.Hour
)

var schemaStmts = []string{
	`CREATE TABLE IF NOT EXISTS nodes(
		path TEXT PRIMARY KEY,
		kind TEXT NOT NULL CHECK(kind IN ('file','dir')),
		body TEXT NOT NULL DEFAULT '',
		size INTEGER NOT NULL DEFAULT 0,
		mtime TEXT NOT NULL,
		title TEXT NOT NULL DEFAULT '',
		summary TEXT NOT NULL DEFAULT '',
		tags TEXT NOT NULL DEFAULT '',
		updated TEXT NOT NULL DEFAULT '')`,
	`CREATE TABLE IF NOT EXISTS versions(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		path TEXT NOT NULL,
		kind TEXT NOT NULL CHECK(kind IN ('history','trash')),
		ts TEXT NOT NULL,
		size INTEGER NOT NULL,
		body TEXT NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS versions_idx ON versions(kind, path, id)`,
	`CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(path, title, tags, summary, body, tokenize='unicode61 remove_diacritics 2')`,
	`CREATE TRIGGER IF NOT EXISTS nodes_ai AFTER INSERT ON nodes WHEN new.kind='file' BEGIN
		INSERT INTO fts(rowid,path,title,tags,summary,body) VALUES(new.rowid,new.path,new.title,new.tags,new.summary,new.body); END`,
	`CREATE TRIGGER IF NOT EXISTS nodes_ad AFTER DELETE ON nodes WHEN old.kind='file' BEGIN
		DELETE FROM fts WHERE rowid=old.rowid; END`,
	`CREATE TRIGGER IF NOT EXISTS nodes_au AFTER UPDATE ON nodes WHEN new.kind='file' BEGIN
		DELETE FROM fts WHERE rowid=old.rowid;
		INSERT INTO fts(rowid,path,title,tags,summary,body) VALUES(new.rowid,new.path,new.title,new.tags,new.summary,new.body); END`,
}

type KBStore struct {
	db   *sql.DB
	path string
}

func dsn(p string) string {
	return "file:" + p + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
}

func openKBStore(p string) (*KBStore, error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(p))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, s := range schemaStmts {
		if _, err := db.Exec(s); err != nil {
			db.Close()
			return nil, fmt.Errorf("kb schema: %w", err)
		}
	}
	_ = os.Chmod(p, 0o600)
	return &KBStore{db: db, path: p}, nil
}

func (k *KBStore) Close() error { return k.db.Close() }

func nowStr() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// prefixRange returns [lo,hi) such that lo <= path < hi selects everything below rel/.
func prefixRange(rel string) (string, string) { return rel + "/", rel + "0" }

func (k *KBStore) metaGet(key string) string {
	var v string
	_ = k.db.QueryRow(`SELECT v FROM meta WHERE k=?`, key).Scan(&v)
	return v
}

func (k *KBStore) metaSet(key, v string) error {
	_, err := k.db.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, key, v)
	return err
}

type fileStat struct {
	size  int64
	mtime time.Time
	dir   bool
}

func (s *fileStat) Size() int64        { return s.size }
func (s *fileStat) ModTime() time.Time { return s.mtime }
func (s *fileStat) IsDir() bool        { return s.dir }

func (k *KBStore) dirExists(q interface {
	QueryRow(string, ...any) *sql.Row
}, rel string) bool {
	lo, hi := prefixRange(rel)
	var n int
	_ = q.QueryRow(`SELECT count(*) FROM (SELECT 1 FROM nodes WHERE path=? AND kind='dir' UNION ALL SELECT 1 FROM nodes WHERE path>=? AND path<? LIMIT 1)`, rel, lo, hi).Scan(&n)
	return n > 0
}

func (k *KBStore) stat(rel string) (*fileStat, error) {
	var kind, mt string
	var size int64
	err := k.db.QueryRow(`SELECT kind,size,mtime FROM nodes WHERE path=?`, rel).Scan(&kind, &size, &mt)
	if err == nil {
		t, _ := time.Parse(time.RFC3339Nano, mt)
		return &fileStat{size: size, mtime: t, dir: kind == "dir"}, nil
	}
	if rel == "." || k.dirExists(k.db, rel) {
		return &fileStat{dir: true}, nil
	}
	return nil, fs.ErrNotExist
}

func (k *KBStore) list(rel string, depth int) ([]listEntry, error) {
	var rows *sql.Rows
	var err error
	base := 0
	if rel == "." {
		rows, err = k.db.Query(`SELECT path,kind,size,mtime FROM nodes ORDER BY path`)
	} else {
		lo, hi := prefixRange(rel)
		base = strings.Count(rel, "/") + 1
		rows, err = k.db.Query(`SELECT path,kind,size,mtime FROM nodes WHERE path>=? AND path<? ORDER BY path`, lo, hi)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []listEntry
	for rows.Next() {
		var p, kind, mt string
		var size int64
		if err := rows.Scan(&p, &kind, &size, &mt); err != nil {
			return nil, err
		}
		parts := strings.Split(p, "/")
		for lvl := 1; base+lvl <= len(parts) && lvl <= depth; lvl++ {
			sub := strings.Join(parts[:base+lvl], "/")
			if seen[sub] {
				continue
			}
			seen[sub] = true
			if base+lvl == len(parts) {
				t := "file"
				if kind == "dir" {
					t = "dir"
				}
				out = append(out, listEntry{sub, t, size, mt})
			} else {
				out = append(out, listEntry{sub, "dir", 0, ""})
			}
			if len(out) >= 1000 {
				return nil, errors.New("too many entries (limit 1000); narrow the path")
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 && rel != "." {
		if _, err := k.stat(rel); err != nil {
			return nil, errors.New("not found")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (k *KBStore) read(rel string, off, n int64) (string, bool, error) {
	var kind, body string
	if err := k.db.QueryRow(`SELECT kind,body FROM nodes WHERE path=?`, rel).Scan(&kind, &body); err != nil {
		return "", false, errors.New("not found")
	}
	if kind == "dir" {
		return "", false, errors.New("is a directory")
	}
	if n <= 0 || n > maxRead {
		n = maxRead
	}
	b := []byte(body)
	if off < 0 || off > int64(len(b)) {
		off = int64(len(b))
	}
	end := off + n
	if end > int64(len(b)) {
		end = int64(len(b))
	}
	return string(b[off:end]), end < int64(len(b)), nil
}

func (k *KBStore) snapshot(tx *sql.Tx, kind, rel, body string) error {
	if _, err := tx.Exec(`INSERT INTO versions(path,kind,ts,size,body) VALUES(?,?,?,?,?)`, rel, kind, nowStr(), len(body), body); err != nil {
		return err
	}
	if kind == "history" {
		_, err := tx.Exec(`DELETE FROM versions WHERE kind='history' AND path=? AND id NOT IN (SELECT id FROM versions WHERE kind='history' AND path=? ORDER BY id DESC LIMIT ?)`, rel, rel, histKeepDB)
		return err
	}
	return nil
}

func (k *KBStore) write(rel, content, mode string) (string, error) {
	if strings.IndexByte(content, 0) >= 0 {
		return "", errors.New("content must be text (no NUL bytes)")
	}
	if len(content) > maxWrite {
		return "", fmt.Errorf("content too large (limit %d bytes per call)", maxWrite)
	}
	if mode != "create" && mode != "overwrite" && mode != "append" {
		return "", errors.New("mode must be create, overwrite or append")
	}
	tx, err := k.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		var kind string
		if tx.QueryRow(`SELECT kind FROM nodes WHERE path=?`, strings.Join(parts[:i], "/")).Scan(&kind) == nil && kind == "file" {
			return "", fmt.Errorf("parent %q is a file", strings.Join(parts[:i], "/"))
		}
	}
	var kind, body string
	err = tx.QueryRow(`SELECT kind,body FROM nodes WHERE path=?`, rel).Scan(&kind, &body)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if exists && kind == "dir" {
		return "", errors.New("target is a directory")
	}
	if !exists && k.dirExists(tx, rel) {
		return "", errors.New("target is a directory")
	}
	newBody := content
	switch mode {
	case "create":
		if exists {
			return "", errors.New("file exists; use mode=overwrite or append")
		}
	case "append":
		if exists {
			if len(body)+len(content) > maxFileSize {
				return "", errors.New("file would exceed size limit")
			}
			newBody = body + content
		}
	}
	if exists && newBody == body {
		return fmt.Sprintf("unchanged kb:%s", rel), nil
	}
	if exists {
		if err := k.snapshot(tx, "history", rel, body); err != nil {
			return "", fmt.Errorf("history snapshot failed, write aborted: %w", err)
		}
	}
	d := makeDoc(rel, newBody)
	_, err = tx.Exec(`INSERT INTO nodes(path,kind,body,size,mtime,title,summary,tags,updated) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET kind='file', body=excluded.body, size=excluded.size, mtime=excluded.mtime,
		title=excluded.title, summary=excluded.summary, tags=excluded.tags, updated=excluded.updated`,
		rel, "file", newBody, len(newBody), nowStr(), d.Title, d.Summary, strings.Join(d.Tags, ","), d.Updated)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %d bytes to kb:%s", len(content), rel), nil
}

func (k *KBStore) remove(rel string) (string, error) {
	tx, err := k.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var kind, body string
	err = tx.QueryRow(`SELECT kind,body FROM nodes WHERE path=?`, rel).Scan(&kind, &body)
	switch {
	case err == nil && kind == "file":
		if err := k.snapshot(tx, "trash", rel, body); err != nil {
			return "", fmt.Errorf("trash copy failed, delete aborted: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM nodes WHERE path=?`, rel); err != nil {
			return "", err
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return fmt.Sprintf("removed kb:%s (copy kept in trash; see kb_history)", rel), nil
	case err == nil || errors.Is(err, sql.ErrNoRows):
		lo, hi := prefixRange(rel)
		var n int
		_ = tx.QueryRow(`SELECT count(*) FROM nodes WHERE path>=? AND path<?`, lo, hi).Scan(&n)
		if n > 0 {
			return "", errors.New("directory not empty")
		}
		res, err := tx.Exec(`DELETE FROM nodes WHERE path=? AND kind='dir'`, rel)
		if err != nil {
			return "", err
		}
		if c, _ := res.RowsAffected(); c == 0 {
			return "", errors.New("not found")
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return fmt.Sprintf("removed kb:%s", rel), nil
	default:
		return "", err
	}
}

func (k *KBStore) mkdir(rel string) error {
	tx, err := k.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	parts := strings.Split(rel, "/")
	for i := 1; i <= len(parts); i++ {
		p := strings.Join(parts[:i], "/")
		var kind string
		if tx.QueryRow(`SELECT kind FROM nodes WHERE path=?`, p).Scan(&kind) == nil {
			if kind == "file" {
				return fmt.Errorf("%q is a file", p)
			}
			continue
		}
		if _, err := tx.Exec(`INSERT INTO nodes(path,kind,mtime) VALUES(?,'dir',?)`, p, nowStr()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// search is a case-insensitive line search (max 100 matching lines).
func (k *KBStore) search(rel, q string) ([]string, error) {
	var rows *sql.Rows
	var err error
	if rel == "." {
		rows, err = k.db.Query(`SELECT path,body FROM nodes WHERE kind='file' ORDER BY path`)
	} else {
		lo, hi := prefixRange(rel)
		rows, err = k.db.Query(`SELECT path,body FROM nodes WHERE kind='file' AND (path=? OR (path>=? AND path<?)) ORDER BY path`, rel, lo, hi)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	q = strings.ToLower(q)
	var out []string
	for rows.Next() && len(out) < 100 {
		var p, b string
		if err := rows.Scan(&p, &b); err != nil {
			return nil, err
		}
		for i, line := range strings.Split(b, "\n") {
			if strings.Contains(strings.ToLower(line), q) {
				out = append(out, fmt.Sprintf("%s:%d: %s", p, i+1, clip(line, 200)))
				if len(out) >= 100 {
					break
				}
			}
		}
	}
	return out, rows.Err()
}

// docs returns the markdown notes below base (logs skipped unless includeLogs); paths, if non-nil, restricts the set.
func (k *KBStore) docs(base string, includeLogs bool, paths []string) ([]kbDoc, error) {
	q := `SELECT path,body FROM nodes WHERE kind='file' AND path LIKE '%.md'`
	var args []any
	if base != "." {
		lo, hi := prefixRange(base)
		q += ` AND (path=? OR (path>=? AND path<?))`
		args = append(args, base, lo, hi)
	}
	if paths != nil {
		if len(paths) == 0 {
			return nil, nil
		}
		q += ` AND path IN (` + strings.TrimSuffix(strings.Repeat("?,", len(paths)), ",") + `)`
		for _, p := range paths {
			args = append(args, p)
		}
	}
	rows, err := k.db.Query(q+` ORDER BY path LIMIT ?`, append(args, kbMaxDocs)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []kbDoc
	for rows.Next() {
		var p, b string
		if err := rows.Scan(&p, &b); err != nil {
			return nil, err
		}
		if !includeLogs && (strings.Contains(p, "/log/") || strings.HasPrefix(p, "log/")) {
			continue
		}
		out = append(out, makeDoc(p, b))
	}
	return out, rows.Err()
}

// ftsPaths returns the notes matching every word (prefix match), best first; errors yield nil (caller falls back).
func (k *KBStore) ftsPaths(words []string) []string {
	var parts []string
	for _, w := range words {
		w = strings.ReplaceAll(w, `"`, `""`)
		if strings.TrimSpace(w) == "" {
			continue
		}
		parts = append(parts, `"`+w+`"*`)
	}
	if len(parts) == 0 {
		return nil
	}
	rows, err := k.db.Query(`SELECT path FROM fts WHERE fts MATCH ? ORDER BY bm25(fts, 0.0, 5.0, 5.0, 3.0, 1.0) LIMIT 300`, strings.Join(parts, " "))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if rows.Scan(&p) == nil {
			out = append(out, p)
		}
	}
	return out
}

type verEntry struct {
	ID   int64  `json:"id"`
	Path string `json:"path"`
	Time string `json:"time"`
	Size int64  `json:"size"`
}

func (k *KBStore) versions(kind, rel string, limit int) ([]verEntry, error) {
	if limit <= 0 || limit > 300 {
		limit = 100
	}
	q := `SELECT id,path,ts,size FROM versions WHERE kind=?`
	args := []any{kind}
	if rel != "" && rel != "." {
		q += ` AND path=?`
		args = append(args, rel)
	}
	rows, err := k.db.Query(q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []verEntry{}
	for rows.Next() {
		var v verEntry
		if err := rows.Scan(&v.ID, &v.Path, &v.Time, &v.Size); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (k *KBStore) versionBody(id int64) (string, string, string, error) {
	var p, kind, body string
	if err := k.db.QueryRow(`SELECT path,kind,body FROM versions WHERE id=?`, id).Scan(&p, &kind, &body); err != nil {
		return "", "", "", errors.New("version not found")
	}
	return p, kind, body, nil
}

// restore writes a stored version back as the current content (the replaced content goes to history).
func (k *KBStore) restore(id int64) (string, error) {
	p, _, body, err := k.versionBody(id)
	if err != nil {
		return "", err
	}
	if _, err := k.write(p, body, "overwrite"); err != nil {
		return "", err
	}
	return fmt.Sprintf("restored kb:%s from version %d", p, id), nil
}

func (k *KBStore) pruneTrash() {
	cut := time.Now().Add(-trashMaxAge).UTC().Format(time.RFC3339Nano)
	_, _ = k.db.Exec(`DELETE FROM versions WHERE kind='trash' AND ts<?`, cut)
	_, _ = k.db.Exec(`DELETE FROM versions WHERE kind='trash' AND id NOT IN (SELECT id FROM versions WHERE kind='trash' ORDER BY id DESC LIMIT ?)`, trashKeep)
}

type kbStats struct {
	Files, History, Trash int
	Bytes, DBBytes        int64
	ByDir                 []*dirStat
	Recent                []recentFile
	Oldest                string
}

func (k *KBStore) stats() (*kbStats, error) {
	st := &kbStats{}
	byDir := map[string]*dirStat{}
	rows, err := k.db.Query(`SELECT path,size,mtime FROM nodes WHERE kind='file'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all []recentFile
	for rows.Next() {
		var p, mt string
		var sz int64
		if err := rows.Scan(&p, &sz, &mt); err != nil {
			return nil, err
		}
		st.Files++
		st.Bytes += sz
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
		ds.Bytes += sz
		all = append(all, recentFile{p, mt, sz})
		if st.Oldest == "" || mt < st.Oldest {
			st.Oldest = mt
		}
	}
	for _, d := range byDir {
		st.ByDir = append(st.ByDir, d)
	}
	sort.Slice(st.ByDir, func(i, j int) bool { return st.ByDir[i].Name < st.ByDir[j].Name })
	sort.Slice(all, func(i, j int) bool { return all[i].MTime > all[j].MTime })
	if len(all) > 10 {
		all = all[:10]
	}
	st.Recent = all
	_ = k.db.QueryRow(`SELECT count(*) FROM versions WHERE kind='history'`).Scan(&st.History)
	_ = k.db.QueryRow(`SELECT count(*) FROM versions WHERE kind='trash'`).Scan(&st.Trash)
	if fi, err := os.Stat(k.path); err == nil {
		st.DBBytes = fi.Size()
	}
	return st, nil
}

// ---- import / export ----

// importDir loads text files from a directory tree into the store. Legacy .history/.trash files become versions.
// Existing notes are kept unless force is set.
func (k *KBStore) importDir(dir string, force bool) (notes, vers, skipped int, err error) {
	if _, e := os.Stat(dir); e != nil {
		return 0, 0, 0, nil
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, e := filepath.Rel(dir, p)
		if e != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		fi, e := d.Info()
		if e != nil || fi.Size() > maxRead {
			skipped++
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil || strings.IndexByte(string(b), 0) >= 0 {
			skipped++
			return nil
		}
		for _, kind := range []string{"history", "trash"} {
			pref := "." + kind + "/"
			if !strings.HasPrefix(rel, pref) {
				continue
			}
			n := strings.TrimPrefix(rel, pref)
			if len(n) <= tsLen+1 || n[len(n)-tsLen-1] != '.' {
				skipped++
				return nil
			}
			ts, pe := time.Parse("20060102T150405.000", n[len(n)-tsLen:])
			if pe != nil {
				skipped++
				return nil
			}
			orig := strings.ReplaceAll(n[:len(n)-tsLen-1], "__", "/")
			if _, e := k.db.Exec(`INSERT INTO versions(path,kind,ts,size,body) VALUES(?,?,?,?,?)`, orig, kind, ts.UTC().Format(time.RFC3339Nano), len(b), string(b)); e == nil {
				vers++
			}
			return nil
		}
		if strings.HasPrefix(rel, ".") {
			skipped++
			return nil
		}
		cl, e := cleanRel(rel)
		if e != nil || cl == "." || reserved(cl) {
			skipped++
			return nil
		}
		if !force {
			var one int
			if k.db.QueryRow(`SELECT 1 FROM nodes WHERE path=?`, cl).Scan(&one) == nil {
				skipped++
				return nil
			}
		}
		if _, e := k.write(cl, string(b), "overwrite"); e != nil {
			skipped++
			return nil
		}
		notes++
		return nil
	})
	return
}

// exportDir writes every note as a plain file below dir (readable fallback copy).
func (k *KBStore) exportDir(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil { // an empty database must still produce an (empty) export
		return 0, err
	}
	rows, err := k.db.Query(`SELECT path,body FROM nodes WHERE kind='file' ORDER BY path`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var p, b string
		if err := rows.Scan(&p, &b); err != nil {
			return n, err
		}
		cl, e := cleanRel(p)
		if e != nil || cl == "." {
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(cl))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return n, err
		}
		if err := os.WriteFile(dst, []byte(b), 0o640); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

// ---- backups ----

const snapPrefix, snapSuffix = "kb-", ".db"

type BackupInfo struct {
	Name   string `json:"name"`
	Time   string `json:"time"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifySnapshot opens a snapshot read-only, runs integrity_check and returns the note count.
func verifySnapshot(p string) (int, error) {
	db, err := sql.Open("sqlite", "file:"+p+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var res string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&res); err != nil {
		return 0, err
	}
	if res != "ok" {
		return 0, fmt.Errorf("integrity_check: %s", res)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM nodes WHERE kind='file'`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// backup makes a consistent snapshot (VACUUM INTO), verifies it, writes a sha256 sidecar and applies retention.
func (k *KBStore) backup(dir string) (BackupInfo, error) {
	var bi BackupInfo
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return bi, err
	}
	name := snapPrefix + time.Now().UTC().Format("20060102-150405") + snapSuffix
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		return bi, errors.New("snapshot with this timestamp exists; retry in a second")
	}
	if _, err := k.db.Exec(`VACUUM INTO ?`, dst); err != nil {
		_ = os.Remove(dst)
		return bi, fmt.Errorf("snapshot failed: %w", err)
	}
	if _, err := verifySnapshot(dst); err != nil {
		_ = os.Remove(dst)
		return bi, fmt.Errorf("snapshot verification failed, removed: %w", err)
	}
	_ = os.Chmod(dst, 0o600)
	sum, err := fileSHA(dst)
	if err != nil {
		return bi, err
	}
	_ = os.WriteFile(dst+".sha256", []byte(sum+"  "+name+"\n"), 0o600)
	fi, _ := os.Stat(dst)
	retainSnapshots(dir, 14, 8, 3)
	return BackupInfo{Name: name, Time: fi.ModTime().UTC().Format(time.RFC3339), Size: fi.Size(), SHA256: sum}, nil
}

func listSnapshots(dir string) []BackupInfo {
	ents, _ := os.ReadDir(dir)
	var out []BackupInfo
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, snapPrefix) || !strings.HasSuffix(n, snapSuffix) {
			continue
		}
		t, err := time.Parse("20060102-150405", strings.TrimSuffix(strings.TrimPrefix(n, snapPrefix), snapSuffix))
		if err != nil {
			continue
		}
		bi := BackupInfo{Name: n, Time: t.UTC().Format(time.RFC3339)}
		if fi, err := e.Info(); err == nil {
			bi.Size = fi.Size()
		}
		if b, err := os.ReadFile(filepath.Join(dir, n+".sha256")); err == nil {
			bi.SHA256 = strings.Fields(string(b) + " ")[0]
		}
		out = append(out, bi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

// retainSnapshots keeps: the newest `last` snapshots, the newest per day for `days` days and the newest per ISO week for `weeks` weeks.
func retainSnapshots(dir string, days, weeks, last int) {
	snaps := listSnapshots(dir) // newest first
	keep := map[string]bool{}
	seenDay, seenWeek := map[string]bool{}, map[string]bool{}
	now := time.Now().UTC()
	for i, s := range snaps {
		t, _ := time.Parse(time.RFC3339, s.Time)
		if i < last {
			keep[s.Name] = true
		}
		day := t.Format("2006-01-02")
		if now.Sub(t) <= time.Duration(days)*24*time.Hour && !seenDay[day] {
			seenDay[day], keep[s.Name] = true, true
		}
		y, w := t.ISOWeek()
		wk := fmt.Sprintf("%d-%02d", y, w)
		if now.Sub(t) <= time.Duration(weeks)*7*24*time.Hour && !seenWeek[wk] {
			seenWeek[wk], keep[s.Name] = true, true
		}
	}
	for _, s := range snaps {
		if !keep[s.Name] {
			_ = os.Remove(filepath.Join(dir, s.Name))
			_ = os.Remove(filepath.Join(dir, s.Name+".sha256"))
		}
	}
}

// backupDue reports whether the newest snapshot is older than maxAge.
func backupDue(dir string, maxAge time.Duration) bool {
	s := listSnapshots(dir)
	if len(s) == 0 {
		return true
	}
	t, _ := time.Parse(time.RFC3339, s[0].Time)
	return time.Since(t) > maxAge
}

// refreshExport rewrites <dir>/export-latest with plain files (a readable copy independent of SQLite).
func (k *KBStore) refreshExport(dir string) (int, error) {
	tmp := filepath.Join(dir, "export-new")
	final := filepath.Join(dir, "export-latest")
	_ = os.RemoveAll(tmp)
	n, err := k.exportDir(tmp)
	if err != nil {
		_ = os.RemoveAll(tmp)
		return n, err
	}
	_ = os.RemoveAll(final)
	return n, os.Rename(tmp, final)
}

// restoreSnapshot replaces the live database file with a verified snapshot. The service must be stopped.
func restoreSnapshot(livePath, snap string) error {
	if _, err := verifySnapshot(snap); err != nil {
		return fmt.Errorf("snapshot is not usable: %w", err)
	}
	if b, err := os.ReadFile(snap + ".sha256"); err == nil {
		want := strings.Fields(string(b) + " ")[0]
		got, err := fileSHA(snap)
		if err != nil || got != want {
			return errors.New("sha256 mismatch: snapshot changed after it was made")
		}
	}
	if _, err := os.Stat(livePath); err == nil {
		keep := livePath + ".before-restore-" + time.Now().UTC().Format("20060102-150405")
		cur, err := openKBStore(livePath)
		if err != nil {
			return err
		}
		_, e := cur.db.Exec(`VACUUM INTO ?`, keep)
		cur.Close()
		if e != nil {
			return fmt.Errorf("could not save the current database first: %w", e)
		}
		fmt.Println("current database saved as", keep)
	}
	tmp := livePath + ".restoring"
	in, err := os.Open(snap)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Remove(livePath + "-wal")
	_ = os.Remove(livePath + "-shm")
	return os.Rename(tmp, livePath)
}
