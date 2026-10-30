package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Knowledge-base helpers: notes are plain markdown files with an optional frontmatter
// (title, summary, tags, updated). The index is derived from the files on every call,
// so the files stay the single source of truth and can be edited by hand.

const (
	kbMaxDocs  = 2000
	kbMaxIndex = 300
	kbMaxEntry = 4000
)

type kbDoc struct {
	Path    string
	Title   string
	Summary string
	Updated string
	Tags    []string
	Body    string
}

// parseFM splits an optional "---" frontmatter block (flat "key: value" lines) from the body.
func parseFM(s string) (map[string]string, string) {
	fm := map[string]string{}
	if !strings.HasPrefix(s, "---\n") {
		return fm, s
	}
	rest := s[4:]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return fm, s
	}
	for _, line := range strings.Split(rest[:end], "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fm[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	body := rest[end+4:]
	body = strings.TrimPrefix(body, "\n")
	return fm, body
}

func splitTags(v string) []string {
	v = strings.Trim(strings.TrimSpace(v), "[]")
	var out []string
	for _, t := range strings.Split(v, ",") {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func makeDoc(p, content string) kbDoc {
	fm, body := parseFM(content)
	d := kbDoc{Path: p, Body: body, Updated: fm["updated"], Tags: splitTags(fm["tags"]), Title: fm["title"], Summary: fm["summary"]}
	if d.Title == "" || d.Summary == "" {
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "# ") {
				if d.Title == "" {
					d.Title = strings.TrimSpace(line[2:])
				}
				continue
			}
			if d.Summary == "" && !strings.HasPrefix(line, "#") {
				d.Summary = clip(line, 140)
			}
			if d.Title != "" && d.Summary != "" {
				break
			}
		}
	}
	if d.Title == "" {
		d.Title = path.Base(p)
	}
	return d
}

// loadKB returns the markdown notes below base. Log notes (log/ directories) are skipped unless includeLogs is set.
func (f *FS) loadKB(base string, includeLogs bool) ([]kbDoc, error) {
	base, err := cleanRel(base)
	if err != nil {
		return nil, err
	}
	return f.kb.docs(base, includeLogs, nil)
}

// isDocNote reports notes kept under a docs/ directory (long imported documents, hidden from the default index).
func isDocNote(p string) bool { return strings.HasPrefix(p, "docs/") || strings.Contains(p, "/docs/") }

func (f *FS) kbIndex(base string, includeLogs, includeDocs bool) (string, error) {
	all, err := f.loadKB(base, includeLogs)
	if err != nil {
		return "", err
	}
	docs := all[:0:0]
	hidden := 0
	for _, d := range all {
		if !includeDocs && isDocNote(d.Path) {
			hidden++
			continue
		}
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		return "(no notes)", nil
	}
	var sb strings.Builder
	for i, d := range docs {
		if i >= kbMaxIndex {
			fmt.Fprintf(&sb, "[truncated at %d of %d notes; narrow with path]\n", kbMaxIndex, len(docs))
			break
		}
		fmt.Fprintf(&sb, "%s | %s", d.Path, d.Title)
		if len(d.Tags) > 0 {
			fmt.Fprintf(&sb, " [%s]", strings.Join(d.Tags, ","))
		}
		if d.Updated != "" {
			fmt.Fprintf(&sb, " (%s)", d.Updated)
		}
		if d.Summary != "" {
			fmt.Fprintf(&sb, " — %s", d.Summary)
		}
		sb.WriteString("\n")
	}
	if hidden > 0 {
		fmt.Fprintf(&sb, "[%d docs/ notes hidden; include_docs=true lists them, or read a card's docs list]\n", hidden)
	}
	return sb.String(), nil
}

type kbHeading struct {
	Line, Level, Bytes int
	Title              string
}

// headings parses markdown headings outside code fences; Bytes is the size of each section.
func headings(s string) []kbHeading {
	var hs []kbHeading
	lines := strings.Split(s, "\n")
	fence := false
	offs := make([]int, len(lines)+1)
	for i, l := range lines {
		offs[i+1] = offs[i] + len(l) + 1
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			fence = !fence
			continue
		}
		if fence || !strings.HasPrefix(l, "#") {
			continue
		}
		lv := len(l) - len(strings.TrimLeft(l, "#"))
		if lv > 6 || len(l) <= lv || l[lv] != ' ' {
			continue
		}
		hs = append(hs, kbHeading{Line: i + 1, Level: lv, Title: strings.TrimSpace(l[lv:])})
	}
	for i := range hs {
		end := len(s)
		for j := i + 1; j < len(hs); j++ {
			if hs[j].Level <= hs[i].Level {
				end = offs[hs[j].Line-1]
				break
			}
		}
		hs[i].Bytes = end - offs[hs[i].Line-1]
	}
	return hs
}

func tocText(p, s string) string {
	hs := headings(s)
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: %d bytes, %d lines\n", p, len(s), strings.Count(s, "\n")+1)
	if len(hs) == 0 {
		sb.WriteString("(no headings)\n")
	}
	for _, h := range hs {
		fmt.Fprintf(&sb, "L%d %s %s (%d B)\n", h.Line, strings.Repeat("#", h.Level), h.Title, h.Bytes)
	}
	return sb.String()
}

// sectionText returns the section whose heading contains want (case-insensitive), up to the next heading of the same or higher level.
func sectionText(s, want string) (string, error) {
	w := strings.ToLower(strings.TrimSpace(strings.TrimLeft(want, "# ")))
	lines := strings.Split(s, "\n")
	for _, h := range headings(s) {
		if !strings.Contains(strings.ToLower(h.Title), w) {
			continue
		}
		start := 0
		for i := 0; i < h.Line-1; i++ {
			start += len(lines[i]) + 1
		}
		end := start + h.Bytes
		if end > len(s) {
			end = len(s)
		}
		return s[start:end], nil
	}
	return "", fmt.Errorf("no heading contains %q (use op=toc)", want)
}

type kbHit struct {
	doc     kbDoc
	score   int
	snippet string
}

// kbFind scores notes for a query: every word must match somewhere (path, title, tags, summary or body).
func (f *FS) kbFind(query string, tags []string, base string, includeLogs bool, limit int) (string, error) {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 && len(tags) == 0 {
		return "", errors.New("give a query and/or tags")
	}
	if limit <= 0 {
		limit = 8
	}
	if limit > 30 {
		limit = 30
	}
	var docs []kbDoc
	if cand := f.kb.ftsPaths(words); len(cand) > 0 {
		// FTS5 narrows the candidates (prefix match on every word); the scorer below ranks and snippets them.
		b, err := cleanRel(base)
		if err != nil {
			return "", err
		}
		docs, err = f.kb.docs(b, includeLogs, cand)
		if err != nil {
			return "", err
		}
	} else {
		var err error
		if docs, err = f.loadKB(base, includeLogs); err != nil { // substring fallback, e.g. "ray" inside "xray"
			return "", err
		}
	}
	var hits []kbHit
next:
	for _, d := range docs {
		for _, t := range tags {
			found := false
			for _, dt := range d.Tags {
				if dt == strings.ToLower(strings.TrimSpace(t)) {
					found = true
				}
			}
			if !found {
				continue next
			}
		}
		pl, tl, sl, bl := strings.ToLower(d.Path), strings.ToLower(d.Title), strings.ToLower(d.Summary), strings.ToLower(d.Body)
		tagStr := strings.Join(d.Tags, " ")
		score := 0
		for _, w := range words {
			s := 0
			if strings.Contains(pl, w) {
				s += 3
			}
			if strings.Contains(tl, w) {
				s += 5
			}
			if strings.Contains(tagStr, w) {
				s += 5
			}
			if strings.Contains(sl, w) {
				s += 3
			}
			if n := strings.Count(bl, w); n > 0 {
				if n > 5 {
					n = 5
				}
				s += n
			}
			if s == 0 {
				continue next
			}
			score += s
		}
		h := kbHit{doc: d, score: score}
		if len(words) > 0 {
			for i, line := range strings.Split(d.Body, "\n") {
				ll := strings.ToLower(line)
				for _, w := range words {
					if strings.Contains(ll, w) {
						h.snippet = fmt.Sprintf("L%d: %s", i+1, clip(strings.TrimSpace(line), 160))
						break
					}
				}
				if h.snippet != "" {
					break
				}
			}
		}
		hits = append(hits, h)
	}
	if len(hits) == 0 {
		return "no matches", nil
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	var sb strings.Builder
	for i, h := range hits {
		if i >= limit {
			fmt.Fprintf(&sb, "[%d more matches; raise limit or refine the query]\n", len(hits)-limit)
			break
		}
		fmt.Fprintf(&sb, "%s | %s | score %d", h.doc.Path, h.doc.Title, h.score)
		if h.snippet != "" {
			fmt.Fprintf(&sb, "\n    %s", h.snippet)
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// kbLog appends a dated entry to <node>/log/YYYY-MM.md and refreshes "updated" in <node>/card.md.
func (f *FS) kbLog(node, entry string) (string, error) {
	node, err := cleanRel(node)
	if err != nil || node == "." || reserved(node) {
		return "", errors.New("node must be a relative directory of a note, e.g. projects/home/hosts/pve")
	}
	entry = strings.TrimSpace(entry)
	if entry == "" || len(entry) > kbMaxEntry {
		return "", fmt.Errorf("entry must be 1-%d characters", kbMaxEntry)
	}
	cardPath := node + "/card.md"
	card, _, err := f.read("kb", cardPath, 0, maxRead)
	if err != nil {
		return "", fmt.Errorf("%s does not exist: create the node's card.md first (fs_write)", cardPath)
	}
	now := time.Now().UTC()
	logPath := fmt.Sprintf("%s/log/%s.md", node, now.Format("2006-01"))
	block := fmt.Sprintf("## %s UTC\n%s\n\n", now.Format("2006-01-02 15:04"), entry)
	if _, _, rerr := f.read("kb", logPath, 0, 1); rerr != nil {
		if _, err := f.write("kb", logPath, fmt.Sprintf("---\ntitle: Log %s — %s\ntags: [log]\n---\n# Log %s\n\n", now.Format("2006-01"), node, now.Format("2006-01"))+block, "create"); err != nil {
			return "", err
		}
	} else if _, err := f.write("kb", logPath, block, "append"); err != nil {
		return "", err
	}
	if upd, ok := setUpdated(card, now.Format("2006-01-02")); ok {
		if _, err := f.write("kb", cardPath, upd, "overwrite"); err != nil {
			return "", fmt.Errorf("log written to %s, but card update failed: %w", logPath, err)
		}
	}
	return fmt.Sprintf("logged to kb:%s", logPath), nil
}

// setUpdated sets the "updated:" key inside an existing frontmatter; it returns false if there is none.
func setUpdated(card, date string) (string, bool) {
	if !strings.HasPrefix(card, "---\n") {
		return card, false
	}
	end := strings.Index(card[4:], "\n---")
	if end < 0 {
		return card, false
	}
	head := card[4 : 4+end]
	lines := strings.Split(head, "\n")
	done := false
	for i, l := range lines {
		if k, _, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "updated") {
			lines[i] = "updated: " + date
			done = true
		}
	}
	if !done {
		lines = append(lines, "updated: "+date)
	}
	return "---\n" + strings.Join(lines, "\n") + card[4+end:], true
}

func kbTools() []tool {
	return []tool{
		{Name: "kb_index", ReadOnly: true,
			Description: "START HERE. Compact map of the knowledge base: one line per note (path | title [tags] (updated) — summary). Cheaper than listing and reading files. Use path to scope to a subtree. Logs are hidden unless include_logs is set.",
			Schema:      obj(map[string]any{"path": prop("string", "subtree, default '.'"), "include_logs": prop("boolean", "also list log/ notes")}),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct {
					Path        string
					IncludeLogs bool `json:"include_logs"`
					IncludeDocs bool `json:"include_docs"`
				}
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, err := a.fsys.kbIndex(x.Path, x.IncludeLogs, x.IncludeDocs)
				return s, map[string]any{"path": x.Path}, err
			}},
		{Name: "kb_find", ReadOnly: true,
			Description: "Ranked search over notes: every word of the query must match (path, title, tags, summary or text). Returns paths with one snippet line each, not whole files. Optional tags filter (all must be present).",
			Schema: obj(map[string]any{"query": prop("string", "space-separated words"), "tags": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "required tags"},
				"path": prop("string", "subtree, default '.'"), "include_logs": prop("boolean", "search log/ notes too (history)"), "limit": prop("integer", "1-30, default 8")}),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct {
					Query       string
					Tags        []string
					Path        string
					IncludeLogs bool `json:"include_logs"`
					Limit       int
				}
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, err := a.fsys.kbFind(x.Query, x.Tags, x.Path, x.IncludeLogs, x.Limit)
				return s, map[string]any{"query": x.Query, "path": x.Path}, err
			}},
		{Name: "kb_history", ReadOnly: true,
			Description: "Version history of a note, or the trash. Without id: list versions (newest first) of 'path' (kind=history) or of deleted notes (kind=trash). With id: return that version's text.",
			Schema: obj(map[string]any{"path": prop("string", "note path (history); optional filter for trash"),
				"kind": map[string]any{"type": "string", "enum": []string{"history", "trash"}}, "id": prop("integer", "version id from the list")}),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct {
					Path, Kind string
					ID         int64
				}
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				lf := map[string]any{"path": x.Path, "id": x.ID}
				if x.ID > 0 {
					p, _, body, err := a.fsys.kb.versionBody(x.ID)
					if err != nil {
						return "", lf, err
					}
					return "# " + p + "\n" + body, lf, nil
				}
				if x.Kind == "" {
					x.Kind = "history"
				}
				if x.Kind != "history" && x.Kind != "trash" {
					return "", lf, errors.New("kind must be history or trash")
				}
				rel := ""
				if x.Path != "" {
					c, err := cleanRel(x.Path)
					if err != nil {
						return "", lf, err
					}
					rel = c
				}
				vs, err := a.fsys.kb.versions(x.Kind, rel, 50)
				if err != nil {
					return "", lf, err
				}
				if len(vs) == 0 {
					return "no versions", lf, nil
				}
				var sb strings.Builder
				for _, v := range vs {
					fmt.Fprintf(&sb, "id=%d\t%s\t%d bytes\t%s\n", v.ID, v.Time, v.Size, v.Path)
				}
				return sb.String(), lf, nil
			}},
		{Name: "kb_restore",
			Description: "Restore a note from a version id (kb_history). The content being replaced is kept in history.",
			Schema:      obj(map[string]any{"id": prop("integer", "version id")}, "id"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct{ ID int64 }
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, err := a.fsys.kb.restore(x.ID)
				return s, map[string]any{"id": x.ID}, err
			}},
		{Name: "kb_log",
			Description: "Append a dated entry to the history of a node (<node>/log/YYYY-MM.md) and refresh 'updated' in <node>/card.md. Use after every change or finding: what was done, the backup/rollback, the result. The node's card.md must exist.",
			Schema:      obj(map[string]any{"node": prop("string", "node directory, e.g. projects/home/hosts/pve"), "entry": prop("string", "what happened, max 4000 chars")}, "node", "entry"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct{ Node, Entry string }
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, err := a.fsys.kbLog(x.Node, x.Entry)
				return s, map[string]any{"node": x.Node, "bytes": len(x.Entry)}, err
			}},
	}
}
