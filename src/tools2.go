package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Combined tools: one schema per area with an "op" selector. Each op is routed to the
// single-purpose implementation (legacyTools), so behaviour and audit stay identical.

const instructions = "Home + hog.cx infrastructure gateway with a knowledge base. Find facts first: kb op=find (words), then read only the needed card " +
	"(fs op=read root=kb). Long notes: fs op=toc, then op=read with section. Cards list related nodes in 'related:'. " +
	"Rules: policies/safety.md. ssh/net: mode=read to inspect; mode=write needs reason + backup_note after a backup. " +
	"Keep outputs small: ssh exec supports grep/head/tail/max_bytes, and in mode=read a trailing '| grep|head|tail|wc -l|sort|uniq' runs on the gateway. " +
	"Several commands: commands[] in one call; long runs: background=true then op=job. After a change: kb op=log on the node (or log_node in the write call)."

type opRoute struct {
	legacy string
	drop   []string // fields that the legacy tool does not accept
}

func routeTool(name, desc string, destructive bool, schema map[string]any, routes map[string]opRoute,
	special func(ctx context.Context, a *App, op string, m map[string]json.RawMessage) (string, map[string]any, bool, error)) tool {
	return tool{Name: name, Description: desc, Destructive: destructive, Schema: schema,
		Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				return "", nil, fmt.Errorf("invalid arguments: %v", err)
			}
			var op string
			if v, ok := m["op"]; ok {
				_ = json.Unmarshal(v, &op)
			}
			delete(m, "op")
			if special != nil {
				if s, lf, handled, err := special(ctx, a, op, m); handled {
					if lf == nil {
						lf = map[string]any{}
					}
					lf["op"] = op
					return s, lf, err
				}
			}
			r, ok := routes[op]
			if !ok {
				ops := make([]string, 0, len(routes))
				for k := range routes {
					ops = append(ops, k)
				}
				sort.Strings(ops)
				return "", nil, fmt.Errorf("op must be one of: %s", strings.Join(ops, ", "))
			}
			for _, d := range r.drop {
				delete(m, d)
			}
			for _, lt := range legacyTools() {
				if lt.Name == r.legacy {
					b, _ := json.Marshal(m)
					s, lf, err := lt.Run(ctx, a, b)
					if lf == nil {
						lf = map[string]any{}
					}
					lf["op"] = op
					return s, lf, err
				}
			}
			return "", nil, errors.New("internal: route not found")
		}}
}

func opProp(ops ...string) map[string]any {
	return map[string]any{"type": "string", "enum": ops}
}

func arr(t, desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": t}, "description": desc}
}

func combinedTools() []tool {
	str := func(d string) map[string]any { return prop("string", d) }
	num := func(d string) map[string]any { return prop("integer", d) }
	flag := func(d string) map[string]any { return prop("boolean", d) }
	writeProps := func(m map[string]any) map[string]any {
		m["mode"] = opProp("read", "write")
		m["reason"] = str("write: why")
		m["backup_note"] = str("write: backup/rollback made")
		return m
	}

	fsT := routeTool("fs",
		"Files. root=kb (SQLite, versions kept) or tmp (14 days). ops: list(path,depth) read(path[,section|offset,length]) toc(path) write(path,content,mode) patch(path,old,new[,replace_all]) append_section(path,section,content) delete(path) move(from,to) search(query[,path]). Prefer patch over rewriting a card.",
		true,
		obj(map[string]any{"op": opProp("list", "read", "toc", "write", "patch", "append_section", "delete", "move", "search"),
			"old": str("patch: exact text"), "new": str("patch: replacement"), "replace_all": flag("patch: all"),
			"root": opProp("kb", "tmp"), "path": str("relative path"), "depth": num("list: 1-6"),
			"section": str("read: heading text to return only that section"), "offset": num("read: byte offset"), "length": num("read: bytes"),
			"content": str("write: text"), "mode": opProp("create", "overwrite", "append"),
			"from": str("move: source"), "to": str("move: destination"), "query": str("search: text")}, "op", "root"),
		map[string]opRoute{"list": {legacy: "fs_list"}, "read": {legacy: "fs_read"}, "write": {legacy: "fs_write"},
			"delete": {legacy: "fs_delete"}, "move": {legacy: "fs_move"}, "search": {legacy: "fs_search"}},
		func(ctx context.Context, a *App, op string, m map[string]json.RawMessage) (string, map[string]any, bool, error) {
			if op == "patch" || op == "append_section" {
				var x struct {
					Root, Path, Old, New, Section, Content string
					ReplaceAll                             bool `json:"replace_all"`
				}
				b, _ := json.Marshal(m)
				if err := decode(b, &x); err != nil {
					return "", nil, true, err
				}
				lf := map[string]any{"root": x.Root, "path": x.Path, "section": x.Section, "bytes": len(x.New) + len(x.Content)}
				s, more, err := a.fsys.read(x.Root, x.Path, 0, maxRead)
				if err != nil {
					return "", lf, true, err
				}
				if more {
					return "", lf, true, errors.New("file larger than 256 KiB: rewrite it with op=write instead")
				}
				var ns, msg string
				if op == "patch" {
					n := 0
					if ns, n, err = patchText(s, x.Old, x.New, x.ReplaceAll); err != nil {
						return "", lf, true, err
					}
					msg = fmt.Sprintf("patched %s:%s (%d replacement(s), %d -> %d bytes)", x.Root, x.Path, n, len(s), len(ns))
				} else {
					if strings.TrimSpace(x.Content) == "" {
						return "", lf, true, errors.New("content is empty")
					}
					if ns, err = appendToSection(s, x.Section, x.Content); err != nil {
						return "", lf, true, err
					}
					msg = fmt.Sprintf("appended %d bytes to section %q of %s:%s", len(x.Content), x.Section, x.Root, x.Path)
				}
				if _, err := a.fsys.write(x.Root, x.Path, ns, "overwrite"); err != nil {
					return "", lf, true, err
				}
				return msg, lf, true, nil
			}
			_, hasSec := m["section"]
			if op != "toc" && !(op == "read" && hasSec) {
				return "", nil, false, nil
			}
			var x struct{ Root, Path, Section string }
			b, _ := json.Marshal(m)
			if err := decode(b, &x); err != nil {
				return "", nil, true, err
			}
			lf := map[string]any{"root": x.Root, "path": x.Path, "section": x.Section}
			s, more, err := a.fsys.read(x.Root, x.Path, 0, maxRead)
			if err != nil {
				return "", lf, true, err
			}
			if op == "toc" {
				t := tocText(x.Path, s)
				if more {
					t += "[file larger than 256 KiB: headings after that are not shown]\n"
				}
				return t, lf, true, nil
			}
			sec, err := sectionText(s, x.Section)
			return sec, lf, true, err
		})

	kbT := routeTool("kb",
		"Knowledge base. ops: find(query words[,tags,path,limit]) — start here; index([path,include_docs,include_logs]) — one line per card; history(path|kind=trash|id) ; restore(id) ; log(node,entry) — dated entry after every change/finding.",
		false,
		obj(map[string]any{"op": opProp("find", "index", "history", "restore", "log"),
			"query": str("find: words, all must match"), "tags": arr("string", "find: required tags"), "path": str("subtree or note path"),
			"limit": num("find: 1-30"), "include_logs": flag("include log/ notes"), "include_docs": flag("index: also docs/ notes"),
			"kind": opProp("history", "trash"), "id": num("history/restore: version id"),
			"node": str("log: node dir, e.g. projects/hogcx"), "entry": str("log: what was done, backup, result")}, "op"),
		map[string]opRoute{"find": {legacy: "kb_find"}, "index": {legacy: "kb_index"}, "history": {legacy: "kb_history"},
			"restore": {legacy: "kb_restore"}, "log": {legacy: "kb_log"}}, nil)

	sshT := routeTool("ssh",
		"SSH to op=hosts aliases. exec(host,command|commands[]): mode=read = restricted, one command per item, trailing '|grep|head|tail|wc -l|sort|uniq' runs on the gateway; mode=write = admin: reason+backup_note, log_node logs to kb, allow_disruptive if flagged. background=true -> op=job(id). Output 8 KiB, start+end kept: grep/head/tail/max_bytes. download/upload(host,remote_path,tmp_path).",
		true,
		obj(writeProps(map[string]any{"op": opProp("hosts", "exec", "job", "download", "upload"),
			"commands": arr("string", "exec: batch (max 20)"), "background": flag("exec: as a job"), "id": str("job id; empty lists"),
			"log_node": str("write: kb node to log to"),
			"host":     str("alias"), "command": str("exec: command line"), "stdin": str("exec: stdin text"), "timeout_sec": num("1-600"),
			"allow_disruptive": flag("write: confirm disruptive"), "grep": str("exec: regexp, keep matching stdout lines"),
			"head": num("exec: first N lines"), "tail": num("exec: last N lines"), "max_bytes": num("exec: up to 65536"),
			"remote_path": str("download/upload: remote file"), "tmp_path": str("download/upload: file under tmp")}), "op"),
		map[string]opRoute{"hosts": {legacy: "hosts_list", drop: []string{"mode"}}, "exec": {legacy: "ssh_exec"},
			"download": {legacy: "ssh_download", drop: []string{"mode", "reason", "backup_note"}}, "upload": {legacy: "ssh_upload", drop: []string{"mode"}}},
		func(ctx context.Context, a *App, op string, m map[string]json.RawMessage) (string, map[string]any, bool, error) {
			if op != "job" {
				return "", nil, false, nil
			}
			var x struct{ ID string }
			b, _ := json.Marshal(m)
			if err := decode(b, &x); err != nil {
				return "", nil, true, err
			}
			s, err := jobs.report(x.ID)
			return s, map[string]any{"job": x.ID}, true, err
		})

	netT := routeTool("net",
		"Network checks from the gateway to any host/port (not loopback or itself). ops: dns(name[,type]) tcp(host,port|ports[,send]) http(url[,method,headers,body]) udp(host,port,send). Payloads, non-GET http and udp need mode=write with reason+backup_note.",
		true,
		obj(writeProps(map[string]any{"op": opProp("dns", "tcp", "http", "udp"),
			"name": str("dns: name or IP"), "type": str("dns: A|AAAA|TXT|MX|CNAME|NS|PTR"),
			"host": str("tcp/udp: IP or name"), "port": num("1-65535"), "ports": arr("integer", "tcp: up to 50 ports"),
			"send": str("tcp/udp: text payload"), "send_hex": str("tcp/udp: hex payload"), "read_bytes": num("tcp: bytes to read"),
			"url": str("http: url"), "method": str("http: GET default"), "headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			"body": str("http: request body"), "max_bytes": num("http: response bytes, default 8192"), "follow_redirects": flag("http"), "insecure_tls": flag("http: skip TLS check"),
			"timeout_sec": num("1-60")}), "op"),
		map[string]opRoute{"dns": {legacy: "net_dns", drop: []string{"mode", "reason", "backup_note"}}, "tcp": {legacy: "net_tcp"},
			"http": {legacy: "net_http"}, "udp": {legacy: "net_udp"}}, nil)

	stT := routeTool("status",
		"Gateway status. ops: server; audit (compact lines; filters host, tool, filter_op, errors, since, grep; full=raw JSON).",
		false,
		obj(map[string]any{"op": opProp("server", "audit"), "lines": num("default 30, max 300"), "host": str("alias"), "tool": str("tool/event"),
			"filter_op": str("op"), "errors": flag("failures only"), "since": str("90m | 2026-10-30T12:00"), "grep": str("regexp"), "full": flag("raw JSON")}, "op"),
		map[string]opRoute{"server": {legacy: "server_status", drop: []string{"lines", "host", "tool", "filter_op", "errors", "since", "grep", "full"}}, "audit": {legacy: "audit_tail"}},
		func(ctx context.Context, a *App, op string, m map[string]json.RawMessage) (string, map[string]any, bool, error) {
			if op != "audit" {
				return "", nil, false, nil
			}
			if v, ok := m["filter_op"]; ok { // "op" itself selects the operation of this tool
				m["op"] = v
				delete(m, "filter_op")
			}
			var x auditQuery
			b, _ := json.Marshal(m)
			if err := decode(b, &x); err != nil {
				return "", nil, true, err
			}
			s, err := a.queryAudit(x)
			return s, map[string]any{"lines": x.Lines, "filter_host": x.Host, "filter_tool": x.Tool, "errors_only": x.Errors, "since": x.Since}, true, err
		})
	stT.ReadOnly = true
	return []tool{kbT, fsT, sshT, netT, stT}
}
