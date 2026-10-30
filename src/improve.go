package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- secret masking (audit log and ssh output) ----

var secretBlock = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`)

var secretTokens = regexp.MustCompile(`\b(cfut_|cfat_|gh[pousr]_|github_pat_|xox[abpr]-|sk-ant-|sk-|glpat-|hf_)[A-Za-z0-9_\-]{16,}|\bAKIA[0-9A-Z]{16}\b`)

// secretAssign matches key=value / key: value pairs whose key names a secret.
var secretAssign = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*"?)(\s*[=:]\s*)("[^"\n]{4,}"|'[^'\n]{4,}'|[^\s"',;&|)}\]]{4,})`)

var secretAuth = regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{8,}`)

// maskSecrets replaces private keys, well-known token formats and secret-looking assignments with ***.
func maskSecrets(s string) string {
	if s == "" {
		return s
	}
	s = secretBlock.ReplaceAllString(s, "-----BEGIN PRIVATE KEY----- *** (masked) -----END PRIVATE KEY-----")
	s = secretTokens.ReplaceAllStringFunc(s, func(m string) string {
		if i := strings.IndexAny(m, "_-"); i > 0 && i < 12 {
			return m[:i+1] + "***"
		}
		return "***"
	})
	s = secretAuth.ReplaceAllString(s, "${1}***")
	s = secretAssign.ReplaceAllStringFunc(s, func(m string) string {
		sm := secretAssign.FindStringSubmatch(m)
		v := sm[3]
		if v == "***" || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "\"$") || strings.Contains(v, "***") {
			return m // a variable reference or already masked
		}
		return sm[1] + sm[2] + "***"
	})
	return s
}

// maskFields masks every string value of an audit event (one level of nesting).
func maskFields(m map[string]any) {
	for k, v := range m {
		switch t := v.(type) {
		case string:
			m[k] = maskSecrets(t)
		case map[string]any:
			maskFields(t)
		}
	}
}

// ---- gateway-side pipeline for read mode ----

// splitPipe splits a command on unquoted single "|" characters. ok is false when there is no pipe.
func splitPipe(cmd string) (parts []string, ok bool) {
	var cur strings.Builder
	q := byte(0)
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else if c == '\\' && q == '"' && i+1 < len(cmd) {
				cur.WriteByte(c)
				i++
				c = cmd[i]
			}
		case c == '\'' || c == '"':
			q = c
		case c == '\\' && i+1 < len(cmd):
			cur.WriteByte(c)
			i++
			c = cmd[i]
		case c == '|':
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				return nil, false // "||" is not a pipe; let the remote shell reject it
			}
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
			ok = true
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, strings.TrimSpace(cur.String()))
	return parts, ok
}

// shellWords splits one filter command into words (single/double quotes and backslash escapes).
func shellWords(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	in, q := false, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			} else {
				cur.WriteByte(c)
			}
		case q == '"':
			if c == '"' {
				q = 0
			} else if c == '\\' && i+1 < len(s) && strings.IndexByte(`"\$`+"`", s[i+1]) >= 0 {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			q, in = c, true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			in = true
		case c == ' ' || c == '\t':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		case strings.IndexByte(";&<>`$()", c) >= 0:
			return nil, fmt.Errorf("character %q is not allowed in a filter", c)
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if q != 0 {
		return nil, errors.New("unterminated quote in filter")
	}
	if in {
		out = append(out, cur.String())
	}
	return out, nil
}

// breToRE converts a POSIX basic regular expression to Go (RE2) syntax.
func breToRE(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			n := p[i+1]
			i++
			if strings.IndexByte("|(){}+?", n) >= 0 {
				b.WriteByte(n) // \| \( \) ... are operators in BRE
			} else {
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			continue
		}
		if strings.IndexByte("|(){}+?", c) >= 0 {
			b.WriteByte('\\') // literal in BRE
		}
		b.WriteByte(c)
	}
	return b.String()
}

type lineFilter func([]string) ([]string, error)

const pipeHelp = "allowed filters after '|' in mode=read: grep [-iEFvcwx] pattern, head/tail [-n N|-N], wc -l, sort [-nru], uniq [-c]"

func countArg(args []string, name string) (int, error) {
	n := 10
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" && i+1 < len(args):
			i++
			a = args[i]
		case strings.HasPrefix(a, "-n"):
			a = a[2:]
		case strings.HasPrefix(a, "-"):
			a = a[1:]
		}
		v, err := strconv.Atoi(strings.TrimPrefix(a, "+"))
		if err != nil || v < 0 {
			return 0, fmt.Errorf("%s: bad count %q", name, args[i])
		}
		n = v
	}
	return n, nil
}

func parseFilter(seg string) (lineFilter, error) {
	w, err := shellWords(seg)
	if err != nil {
		return nil, err
	}
	if len(w) == 0 {
		return nil, errors.New("empty filter after '|'")
	}
	args := w[1:]
	switch w[0] {
	case "grep", "egrep", "fgrep":
		ext, fixed, inv, cnt, ci, word, line := w[0] == "egrep", w[0] == "fgrep", false, false, false, false, false
		var pat []string
		for i := 0; i < len(args); i++ {
			a := args[i]
			if a == "-e" && i+1 < len(args) {
				i++
				pat = append(pat, args[i])
				continue
			}
			if strings.HasPrefix(a, "-") && len(a) > 1 && len(pat) == 0 {
				for _, f := range a[1:] {
					switch f {
					case 'E':
						ext = true
					case 'F':
						fixed = true
					case 'v':
						inv = true
					case 'c':
						cnt = true
					case 'i':
						ci = true
					case 'w':
						word = true
					case 'x':
						line = true
					case 'a', 'h', 's':
					default:
						return nil, fmt.Errorf("grep option -%c is not supported; %s", f, pipeHelp)
					}
				}
				continue
			}
			pat = append(pat, a)
		}
		if len(pat) != 1 {
			return nil, errors.New("grep: exactly one pattern (files are not allowed)")
		}
		p := pat[0]
		switch {
		case fixed:
			p = regexp.QuoteMeta(p)
		case !ext:
			p = breToRE(p)
		}
		if word {
			p = `\b(?:` + p + `)\b`
		}
		if line {
			p = `^(?:` + p + `)$`
		}
		if ci {
			p = `(?i)` + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("grep: %v", err)
		}
		return func(in []string) ([]string, error) {
			out := in[:0:0]
			for _, l := range in {
				if re.MatchString(l) != inv {
					out = append(out, l)
				}
			}
			if cnt {
				return []string{strconv.Itoa(len(out))}, nil
			}
			return out, nil
		}, nil
	case "head", "tail":
		n, err := countArg(args, w[0])
		if err != nil {
			return nil, err
		}
		head := w[0] == "head"
		return func(in []string) ([]string, error) {
			if len(in) <= n {
				return in, nil
			}
			if head {
				return in[:n], nil
			}
			return in[len(in)-n:], nil
		}, nil
	case "wc":
		if len(args) != 1 || args[0] != "-l" {
			return nil, errors.New("wc: only 'wc -l' is supported")
		}
		return func(in []string) ([]string, error) { return []string{strconv.Itoa(len(in))}, nil }, nil
	case "sort":
		num, rev, uniq := false, false, false
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				return nil, errors.New("sort: files are not allowed")
			}
			for _, f := range a[1:] {
				switch f {
				case 'n':
					num = true
				case 'r':
					rev = true
				case 'u':
					uniq = true
				default:
					return nil, fmt.Errorf("sort option -%c is not supported; %s", f, pipeHelp)
				}
			}
		}
		return func(in []string) ([]string, error) {
			out := append([]string(nil), in...)
			key := func(s string) float64 {
				f := strings.Fields(s)
				if len(f) == 0 {
					return 0
				}
				v, _ := strconv.ParseFloat(f[0], 64)
				return v
			}
			sort.SliceStable(out, func(i, j int) bool {
				if num {
					a, b := key(out[i]), key(out[j])
					if a != b {
						return (a < b) != rev
					}
				}
				return (out[i] < out[j]) != rev
			})
			if uniq {
				u := out[:0]
				for i, l := range out {
					if i == 0 || l != out[i-1] {
						u = append(u, l)
					}
				}
				out = u
			}
			return out, nil
		}, nil
	case "uniq":
		cnt := false
		for _, a := range args {
			if a != "-c" {
				return nil, errors.New("uniq: only -c is supported")
			}
			cnt = true
		}
		return func(in []string) ([]string, error) {
			var out []string
			for i := 0; i < len(in); {
				j := i
				for j < len(in) && in[j] == in[i] {
					j++
				}
				if cnt {
					out = append(out, fmt.Sprintf("%7d %s", j-i, in[i]))
				} else {
					out = append(out, in[i])
				}
				i = j
			}
			return out, nil
		}, nil
	}
	return nil, fmt.Errorf("filter %q is not allowed; %s", w[0], pipeHelp)
}

// readPipeline splits a read-mode command into the remote part and gateway-side filters.
func readPipeline(cmd string) (string, []lineFilter, error) {
	parts, ok := splitPipe(cmd)
	if !ok {
		return cmd, nil, nil
	}
	if parts[0] == "" {
		return "", nil, errors.New("empty command before '|'")
	}
	var fs []lineFilter
	for _, p := range parts[1:] {
		f, err := parseFilter(p)
		if err != nil {
			return "", nil, err
		}
		fs = append(fs, f)
	}
	return parts[0], fs, nil
}

func applyFilters(s string, fs []lineFilter) (string, error) {
	if len(fs) == 0 {
		return s, nil
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if s == "" {
		lines = nil
	}
	var err error
	for _, f := range fs {
		if lines, err = f(lines); err != nil {
			return "", err
		}
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// ---- background jobs ----

type sshJob struct {
	ID, Host, Mode, Command string
	Started                 time.Time
	Finished                time.Time
	Done                    bool
	Result                  string
	Err                     string
}

type jobStore struct {
	mu   sync.Mutex
	m    map[string]*sshJob
	seq  int
	runs int
}

var jobs = &jobStore{m: map[string]*sshJob{}}

const (
	maxJobsRunning = 4
	jobKeep        = 2 * time.Hour
)

func (s *jobStore) start(a *App, x execArgs) (*sshJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, j := range s.m {
		if j.Done && time.Since(j.Finished) > jobKeep {
			delete(s.m, id)
		}
	}
	if s.runs >= maxJobsRunning {
		return nil, fmt.Errorf("%d background jobs are already running; poll them with ssh op=job", s.runs)
	}
	s.seq++
	cmd := x.Command
	if len(x.Commands) > 0 {
		cmd = strings.Join(x.Commands, " ;; ")
	}
	j := &sshJob{ID: fmt.Sprintf("j%d-%s", s.seq, randToken(3)), Host: x.Host, Mode: x.Mode, Command: clip(cmd, 200), Started: time.Now()}
	s.m[j.ID] = j
	s.runs++
	x.Background = false
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(maxTimeout+60)*time.Second)
		defer cancel()
		res, err := a.sshRun(ctx, x)
		s.mu.Lock()
		j.Done, j.Finished, j.Result = true, time.Now(), res
		if err != nil {
			j.Err = err.Error()
		}
		s.runs--
		s.mu.Unlock()
		a.audit.log(map[string]any{"ev": "job_done", "job": j.ID, "host": j.Host, "mode": j.Mode, "ok": err == nil, "ms": time.Since(j.Started).Milliseconds(), "out_bytes": len(res)})
	}()
	return j, nil
}

func (s *jobStore) report(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		if len(s.m) == 0 {
			return "no background jobs", nil
		}
		ids := make([]string, 0, len(s.m))
		for k := range s.m {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		var sb strings.Builder
		for _, k := range ids {
			j := s.m[k]
			st := "running " + time.Since(j.Started).Round(time.Second).String()
			if j.Done {
				st = "done in " + j.Finished.Sub(j.Started).Round(time.Second).String()
			}
			fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\t%s\n", j.ID, j.Host, j.Mode, st, j.Command)
		}
		return sb.String(), nil
	}
	j := s.m[id]
	if j == nil {
		return "", errors.New("unknown job id (finished jobs are kept for 2 hours)")
	}
	if !j.Done {
		return fmt.Sprintf("job %s running for %s on %s; poll again later", j.ID, time.Since(j.Started).Round(time.Second), j.Host), nil
	}
	if j.Err != "" {
		return "", fmt.Errorf("job %s failed after %s: %s", j.ID, j.Finished.Sub(j.Started).Round(time.Second), j.Err)
	}
	return fmt.Sprintf("job %s done in %s\n%s", j.ID, j.Finished.Sub(j.Started).Round(time.Second), j.Result), nil
}

// ---- audit query ----

type auditQuery struct {
	Lines  int    `json:"lines"`
	Host   string `json:"host"`
	Tool   string `json:"tool"`
	Op     string `json:"op"`
	Errors bool   `json:"errors"`
	Since  string `json:"since"`
	Grep   string `json:"grep"`
	Full   bool   `json:"full"`
}

func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	for _, f := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("since: use a duration (90m, 2h, 48h) or a UTC time (2026-10-30T12:00)")
}

func compactEvent(e map[string]any) string {
	gs := func(k string) string { v, _ := e[k].(string); return v }
	ts := gs("ts")
	if len(ts) >= 19 {
		ts = ts[5:16] // MM-DDTHH:MM
	}
	ev := gs("ev")
	var sb strings.Builder
	sb.WriteString(ts + " ")
	if ev == "tool" {
		t := gs("tool")
		if op := gs("op"); op != "" {
			t += "/" + op
		}
		sb.WriteString(t)
		for _, k := range []string{"host", "mode"} {
			if v := gs(k); v != "" {
				sb.WriteString(" " + v)
			}
		}
		if ok, _ := e["ok"].(bool); !ok {
			sb.WriteString(" FAIL")
		}
		if ms, ok := e["ms"].(float64); ok && ms >= 1000 {
			fmt.Fprintf(&sb, " %.0fs", ms/1000)
		}
		for _, k := range []string{"command", "commands", "path", "query", "node", "name", "url", "remote", "from", "job"} {
			if v := gs(k); v != "" {
				sb.WriteString(" | " + clip(strings.Join(strings.Fields(v), " "), 120))
				break
			}
		}
		if er := gs("error"); er != "" {
			sb.WriteString(" | err: " + clip(er, 160))
		}
		return sb.String()
	}
	sb.WriteString(ev)
	for _, k := range []string{"ip", "host", "job", "reason", "name", "error", "path", "op"} {
		if v := gs(k); v != "" {
			sb.WriteString(" " + k + "=" + clip(v, 80))
		}
	}
	if v, ok := e["ok"].(bool); ok && !v {
		sb.WriteString(" FAIL")
	}
	return sb.String()
}

// queryAudit returns the newest matching audit events, oldest first.
func (a *App) queryAudit(q auditQuery) (string, error) {
	if q.Lines <= 0 {
		q.Lines = 30
	}
	if q.Lines > 300 {
		q.Lines = 300
	}
	since, err := parseSince(q.Since)
	if err != nil {
		return "", err
	}
	var re *regexp.Regexp
	if q.Grep != "" {
		if re, err = regexp.Compile("(?i)" + q.Grep); err != nil {
			return "", fmt.Errorf("grep: %v", err)
		}
	}
	f, err := os.Open(a.cfg.AuditLog)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > 16<<20 {
		_, _ = f.Seek(-(16 << 20), 2)
	}
	var keep []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		ln := sc.Text()
		var e map[string]any
		if json.Unmarshal([]byte(ln), &e) != nil {
			continue
		}
		gs := func(k string) string { v, _ := e[k].(string); return v }
		if q.Host != "" && gs("host") != q.Host {
			continue
		}
		if q.Tool != "" && gs("tool") != q.Tool && gs("ev") != q.Tool {
			continue
		}
		if q.Op != "" && gs("op") != q.Op {
			continue
		}
		if q.Errors {
			if ok, has := e["ok"].(bool); !has || ok {
				if !strings.Contains(gs("ev"), "fail") && !strings.Contains(gs("ev"), "reject") && !strings.Contains(gs("ev"), "locked") {
					continue
				}
			}
		}
		if !since.IsZero() {
			if t, err := time.Parse(time.RFC3339, gs("ts")); err == nil && t.Before(since) {
				continue
			}
		}
		if re != nil && !re.MatchString(ln) {
			continue
		}
		out := ln
		if !q.Full {
			out = compactEvent(e)
		}
		keep = append(keep, out)
		if len(keep) > q.Lines {
			keep = keep[1:]
		}
	}
	if len(keep) == 0 {
		return "no matching audit events", nil
	}
	s := strings.Join(keep, "\n")
	if q.Full && len(s) > maxOutBytes {
		s = "[oldest lines dropped to fit 64 KiB]\n" + strings.ToValidUTF8(s[len(s)-maxOutBytes:], "")
	}
	return s, nil
}

// ---- kb text edits ----

// patchText replaces old with new exactly once (or every occurrence with all).
func patchText(s, old, new string, all bool) (string, int, error) {
	if old == "" {
		return "", 0, errors.New("old must not be empty")
	}
	n := strings.Count(s, old)
	switch {
	case n == 0:
		return "", 0, errors.New("old text not found (it must match exactly, including spaces and newlines)")
	case n > 1 && !all:
		return "", 0, fmt.Errorf("old text found %d times; add surrounding text to make it unique or set replace_all", n)
	}
	if all {
		return strings.ReplaceAll(s, old, new), n, nil
	}
	return strings.Replace(s, old, new, 1), 1, nil
}

// appendToSection inserts text at the end of the section with the given heading.
func appendToSection(s, heading, text string) (string, error) {
	sec, err := sectionText(s, heading)
	if err != nil {
		return "", err
	}
	i := strings.Index(s, sec)
	if i < 0 {
		return "", errors.New("section not found")
	}
	end := i + len(sec)
	body := strings.TrimRight(sec, "\n")
	trail := sec[len(body):]
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if trail == "" {
		trail = "\n"
	}
	return s[:i] + body + "\n" + text + strings.TrimPrefix(trail, "\n") + s[end:], nil
}
