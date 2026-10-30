package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxWrite    = 2 << 20
	maxFileSize = 10 << 20
	maxRead     = 256 << 10
	histKeep    = 20
)

// Auditor appends JSON lines; secrets are never passed to it.
type Auditor struct {
	mu   sync.Mutex
	f    *os.File
	path string
	size int64
}

const (
	auditMax  = 20 << 20 // rotate at 20 MiB
	auditKeep = 3
)

func openAudit(p string) (*Auditor, error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	st, _ := f.Stat()
	a := &Auditor{f: f, path: p}
	if st != nil {
		a.size = st.Size()
	}
	return a, nil
}

// rotateLocked shifts audit.log -> .1 -> .2 -> .3 and reopens a fresh file.
func (a *Auditor) rotateLocked() {
	_ = a.f.Close()
	for i := auditKeep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", a.path, i), fmt.Sprintf("%s.%d", a.path, i+1))
	}
	_ = os.Rename(a.path, a.path+".1")
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil { // keep logging to the renamed file rather than losing events
		f, _ = os.OpenFile(a.path+".1", os.O_APPEND|os.O_WRONLY, 0o640)
	}
	a.f, a.size = f, 0
}

func (a *Auditor) log(m map[string]any) {
	m["ts"] = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(m)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.size > auditMax {
		a.rotateLocked()
	}
	n, _ := a.f.Write(append(b, '\n'))
	a.size += int64(n)
}

// FS provides traversal-safe access to two roots using os.Root:
// "kb" (persistent notes, history kept on overwrite/delete) and "tmp" (scratch, auto-cleaned).
type FS struct {
	roots map[string]*os.Root // only "tmp" lives on disk
	kb    *KBStore            // "kb" lives in SQLite
	mu    sync.Mutex
}

func openFS(kb *KBStore, tmp string) (*FS, error) {
	f := &FS{roots: map[string]*os.Root{}, kb: kb}
	if err := os.MkdirAll(tmp, 0o750); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(tmp)
	if err != nil {
		return nil, err
	}
	f.roots["tmp"] = r
	return f, nil
}

func (f *FS) root(name string) (*os.Root, error) {
	r, ok := f.roots[name]
	if !ok {
		return nil, errors.New(`root must be "kb" or "tmp"`)
	}
	return r, nil
}

// kbRel validates a kb path; ok is false when root is not "kb".
func (f *FS) kbRel(root, rel string) (string, bool, error) {
	if root != "kb" {
		return "", false, nil
	}
	rel, err := cleanRel(rel)
	return rel, true, err
}

func cleanRel(p string) (string, error) {
	if p == "" || p == "." || p == "/" {
		return ".", nil
	}
	if strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return "", errors.New("path must be relative, without backslashes")
	}
	c := path.Clean(p)
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", errors.New("path escapes the root")
	}
	return c, nil
}

func reserved(rel string) bool {
	return rel == ".history" || rel == ".trash" || strings.HasPrefix(rel, ".history/") || strings.HasPrefix(rel, ".trash/")
}

func mkdirAll(r *os.Root, dir string) error {
	if dir == "." || dir == "" {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(dir, "/") {
		cur = path.Join(cur, part)
		if err := r.Mkdir(cur, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}

type listEntry struct {
	Path  string `json:"path"`
	Type  string `json:"type"`
	Size  int64  `json:"size"`
	MTime string `json:"mtime"`
}

func (f *FS) list(root, rel string, depth int, hidden bool) ([]listEntry, error) {
	if c, ok, err := f.kbRel(root, rel); ok {
		if err != nil {
			return nil, err
		}
		return f.kb.list(c, depth)
	}
	r, err := f.root(root)
	if err != nil {
		return nil, err
	}
	rel, err = cleanRel(rel)
	if err != nil {
		return nil, err
	}
	var out []listEntry
	base := strings.Count(rel, "/")
	if rel == "." {
		base = -1
	}
	err = fs.WalkDir(r.FS(), rel, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == rel {
			return nil
		}
		if !hidden && reserved(p) {
			return fs.SkipDir
		}
		if strings.Count(p, "/")-base > depth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		t := "file"
		if d.IsDir() {
			t = "dir"
		}
		out = append(out, listEntry{p, t, info.Size(), info.ModTime().UTC().Format(time.RFC3339)})
		if len(out) >= 1000 {
			return errors.New("too many entries (limit 1000); narrow the path")
		}
		return nil
	})
	return out, err
}

func (f *FS) read(root, rel string, off, n int64) (string, bool, error) {
	if c, ok, err := f.kbRel(root, rel); ok {
		if err != nil {
			return "", false, err
		}
		return f.kb.read(c, off, n)
	}
	r, err := f.root(root)
	if err != nil {
		return "", false, err
	}
	if rel, err = cleanRel(rel); err != nil {
		return "", false, err
	}
	fh, err := r.Open(rel)
	if err != nil {
		return "", false, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return "", false, err
	}
	if st.IsDir() {
		return "", false, errors.New("is a directory")
	}
	if n <= 0 || n > maxRead {
		n = maxRead
	}
	if _, err := fh.Seek(off, io.SeekStart); err != nil {
		return "", false, err
	}
	buf := make([]byte, n)
	m, _ := io.ReadFull(fh, buf)
	buf = buf[:m]
	if bytes.IndexByte(buf, 0) >= 0 {
		return "", false, errors.New("binary file; not returned as text")
	}
	return string(buf), off+int64(m) < st.Size(), nil
}

func flat(rel string) string { return strings.ReplaceAll(rel, "/", "__") }

// snapshot stores a copy of rel into dir (".history" or ".trash") for the kb root.
func snapshot(r *os.Root, rel, dir string) error {
	src, err := r.Open(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer src.Close()
	if err := mkdirAll(r, dir); err != nil {
		return err
	}
	name := fmt.Sprintf("%s/%s.%s", dir, flat(rel), time.Now().UTC().Format("20060102T150405.000"))
	dst, err := r.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if dir == ".history" { // prune
		ents, _ := fs.ReadDir(r.FS(), ".history")
		var mine []string
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), flat(rel)+".") {
				mine = append(mine, e.Name())
			}
		}
		sort.Strings(mine)
		for len(mine) > histKeep {
			_ = r.Remove(".history/" + mine[0])
			mine = mine[1:]
		}
	}
	return nil
}

func (f *FS) write(root, rel, content, mode string) (string, error) {
	if c, ok, err := f.kbRel(root, rel); ok {
		if err != nil {
			return "", err
		}
		if c == "." || reserved(c) {
			return "", errors.New("invalid target path")
		}
		return f.kb.write(c, content, mode)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.root(root)
	if err != nil {
		return "", err
	}
	if rel, err = cleanRel(rel); err != nil {
		return "", err
	}
	if rel == "." || reserved(rel) {
		return "", errors.New("invalid target path")
	}
	if len(content) > maxWrite {
		return "", fmt.Errorf("content too large (limit %d bytes per call)", maxWrite)
	}
	if err := mkdirAll(r, path.Dir(rel)); err != nil {
		return "", err
	}
	st, serr := r.Stat(rel)
	exists := serr == nil
	if exists && st.IsDir() {
		return "", errors.New("target is a directory")
	}
	flags := os.O_WRONLY
	switch mode {
	case "create":
		if exists {
			return "", errors.New("file exists; use mode=overwrite or append")
		}
		flags |= os.O_CREATE | os.O_EXCL
	case "overwrite":
		flags |= os.O_CREATE | os.O_TRUNC
	case "append":
		flags |= os.O_CREATE | os.O_APPEND
		if exists && st.Size()+int64(len(content)) > maxFileSize {
			return "", errors.New("file would exceed size limit")
		}
	default:
		return "", errors.New("mode must be create, overwrite or append")
	}
	if exists && root == "kb" && mode != "create" {
		if err := snapshot(r, rel, ".history"); err != nil {
			return "", fmt.Errorf("history snapshot failed, write aborted: %w", err)
		}
	}
	fh, err := r.OpenFile(rel, flags, 0o640)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(fh, content); err != nil {
		fh.Close()
		return "", err
	}
	if err := fh.Close(); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %d bytes to %s:%s", len(content), root, rel), nil
}

func (f *FS) remove(root, rel string) (string, error) {
	if c, ok, err := f.kbRel(root, rel); ok {
		if err != nil {
			return "", err
		}
		if c == "." || reserved(c) {
			return "", errors.New("invalid target path")
		}
		return f.kb.remove(c)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.root(root)
	if err != nil {
		return "", err
	}
	if rel, err = cleanRel(rel); err != nil {
		return "", err
	}
	if rel == "." || reserved(rel) {
		return "", errors.New("invalid target path")
	}
	st, err := r.Stat(rel)
	if err != nil {
		return "", err
	}
	if root == "kb" && !st.IsDir() {
		if err := snapshot(r, rel, ".trash"); err != nil {
			return "", fmt.Errorf("trash copy failed, delete aborted: %w", err)
		}
	}
	if err := r.Remove(rel); err != nil { // files and empty directories only
		return "", err
	}
	if root == "kb" {
		return fmt.Sprintf("removed %s:%s (copy kept in .trash)", root, rel), nil
	}
	return fmt.Sprintf("removed %s:%s", root, rel), nil
}

func (f *FS) search(root, rel, q string) ([]string, error) {
	if c, ok, err := f.kbRel(root, rel); ok {
		if err != nil {
			return nil, err
		}
		return f.kb.search(c, q)
	}
	r, err := f.root(root)
	if err != nil {
		return nil, err
	}
	if rel, err = cleanRel(rel); err != nil {
		return nil, err
	}
	q = strings.ToLower(q)
	var out []string
	err = fs.WalkDir(r.FS(), rel, func(p string, d fs.DirEntry, err error) error {
		if err != nil || len(out) >= 100 {
			return nil
		}
		if d.IsDir() {
			if reserved(p) {
				return fs.SkipDir
			}
			return nil
		}
		info, e := d.Info()
		if e != nil || info.Size() > 1<<20 {
			return nil
		}
		b, e := fs.ReadFile(r.FS(), p)
		if e != nil || bytes.IndexByte(b, 0) >= 0 {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(strings.ToLower(line), q) {
				if len(line) > 200 {
					line = line[:200]
				}
				out = append(out, fmt.Sprintf("%s:%d: %s", p, i+1, line))
				if len(out) >= 100 {
					break
				}
			}
		}
		return nil
	})
	return out, err
}

// cleanTmp removes files in tmp older than age.
func (f *FS) cleanTmp(age time.Duration) {
	r := f.roots["tmp"]
	cutoff := time.Now().Add(-age)
	var files []string
	_ = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if i, e := d.Info(); e == nil && i.ModTime().Before(cutoff) {
				files = append(files, p)
			}
		}
		return nil
	})
	for _, p := range files {
		_ = r.Remove(p)
	}
}

// tmpLocalPath returns the OS path of a file under tmp after validating it (for scp).
func (f *FS) tmpLocalPath(rel string) (string, error) {
	rel, err := cleanRel(rel)
	if err != nil || rel == "." {
		return "", errors.New("invalid tmp path")
	}
	return path.Join(f.roots["tmp"].Name(), rel), nil
}
