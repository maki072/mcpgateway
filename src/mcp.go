package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

var supportedProto = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string
	Description string
	Schema      map[string]any
	ReadOnly    bool
	Destructive bool
	Run         func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error)
}

func (a *App) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/.well-known/oauth-protected-resource", a.gate(a.apiNets, a.metaResource))
	m.HandleFunc("/.well-known/oauth-protected-resource/mcp", a.gate(a.apiNets, a.metaResource))
	m.HandleFunc("/.well-known/oauth-authorization-server", a.gate(a.apiNets, a.metaAS))
	m.HandleFunc("/register", a.gate(a.apiNets, a.register))
	m.HandleFunc("/token", a.gate(a.apiNets, a.token))
	m.HandleFunc("/authorize", a.gate(a.loginNets, a.authorize))
	m.HandleFunc("/mcp", a.gate(a.apiNets, a.mcp))
	a.uiRoutes(m)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return secure(m)
}

func (a *App) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, a.cfg.PublicURL))
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (a *App) mcp(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != "https://claude.ai" && o != "https://claude.com" {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	cid, ok := a.st.checkBearer(bearer(r))
	if !ok {
		a.unauthorized(w)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	body = []byte(strings.TrimSpace(string(body)))
	var reqs []rpcReq
	batch := len(body) > 0 && body[0] == '['
	if batch {
		err = json.Unmarshal(body, &reqs)
	} else {
		var one rpcReq
		err = json.Unmarshal(body, &one)
		reqs = []rpcReq{one}
	}
	if err != nil {
		writeJSON(w, 200, rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{-32700, "parse error"}})
		return
	}
	var out []rpcResp
	for _, q := range reqs {
		if len(q.ID) == 0 { // notification or client response: no reply
			continue
		}
		out = append(out, a.dispatch(r, cid, q))
	}
	switch {
	case len(out) == 0:
		w.WriteHeader(http.StatusAccepted)
	case batch:
		writeJSON(w, 200, out)
	default:
		writeJSON(w, 200, out[0])
	}
}

func (a *App) dispatch(r *http.Request, cid string, q rpcReq) rpcResp {
	resp := rpcResp{JSONRPC: "2.0", ID: q.ID}
	switch q.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(q.Params, &p)
		pv := supportedProto[1]
		for _, s := range supportedProto {
			if s == p.ProtocolVersion {
				pv = s
			}
		}
		resp.Result = map[string]any{
			"protocolVersion": pv,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "mcpgw", "version": version},
			"instructions":    instructions,
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		var list []map[string]any
		for _, t := range tools() {
			list = append(list, map[string]any{
				"name": t.Name, "description": t.Description, "inputSchema": t.Schema,
				"annotations": map[string]any{"readOnlyHint": t.ReadOnly, "destructiveHint": t.Destructive, "openWorldHint": false},
			})
		}
		resp.Result = map[string]any{"tools": list}
	case "tools/call":
		resp.Result, resp.Error = a.callTool(r, cid, q.Params)
	default:
		resp.Error = &rpcErr{-32601, "method not found"}
	}
	return resp
}

func (a *App) callTool(r *http.Request, cid string, params json.RawMessage) (any, *rpcErr) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcErr{-32602, "invalid params"}
	}
	var t *tool
	for _, c := range append(tools(), legacyTools()...) {
		if c.Name == p.Name && t == nil {
			cc := c
			t = &cc
		}
	}
	if t == nil {
		return nil, &rpcErr{-32602, "unknown tool"}
	}
	if len(p.Arguments) == 0 {
		p.Arguments = json.RawMessage("{}")
	}
	start := time.Now()
	text, logFields, err := t.Run(r.Context(), a, p.Arguments)
	ev := map[string]any{"ev": "tool", "tool": t.Name, "client": cid, "ip": clientIP(r).String(), "ms": time.Since(start).Milliseconds(), "ok": err == nil}
	for k, v := range logFields {
		ev[k] = v
	}
	if err != nil {
		ev["error"] = err.Error()
		a.audit.log(ev)
		return map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": "Error: " + err.Error()}}}, nil
	}
	ev["out_bytes"] = len(text)
	a.audit.log(ev)
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}, nil
}

// ---- tool schema helpers ----

func prop(typ, desc string) map[string]any { return map[string]any{"type": typ, "description": desc} }

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func rootProp() map[string]any {
	return map[string]any{"type": "string", "enum": []string{"kb", "tmp"},
		"description": `"kb" = persistent knowledge base stored in SQLite (instructions, notes; previous versions and deleted notes are kept, see kb_history); "tmp" = scratch files on disk, removed after 14 days.`}
}

func decode(raw json.RawMessage, v any) error {
	for try := 0; try < 16; try++ {
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		err := d.Decode(v)
		if err == nil {
			return nil
		}
		// Some clients send numbers and booleans as strings when the schema they hold is stale: coerce that field and retry.
		var te *json.UnmarshalTypeError
		if !errors.As(err, &te) || te.Value != "string" || te.Field == "" || strings.Contains(te.Field, ".") {
			return fmt.Errorf("invalid arguments: %w", err)
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return fmt.Errorf("invalid arguments: %w", err)
		}
		var sv string
		if json.Unmarshal(m[te.Field], &sv) != nil {
			return fmt.Errorf("invalid arguments: %w", err)
		}
		sv = strings.TrimSpace(sv)
		var probe any
		if json.Unmarshal([]byte(sv), &probe) != nil {
			return fmt.Errorf("invalid arguments: field %s: expected %s", te.Field, te.Type)
		}
		switch probe.(type) {
		case float64, bool:
		default:
			return fmt.Errorf("invalid arguments: field %s: expected %s", te.Field, te.Type)
		}
		m[te.Field] = json.RawMessage(sv)
		raw, _ = json.Marshal(m)
	}
	return errors.New("invalid arguments")
}

// legacyTools are the single-purpose tools; they stay callable by name but are not listed.
func legacyTools() []tool {
	return append(append(baseTools(), kbTools()...), netTools()...)
}

// tools are the listed, combined tools (fewer schemas in every request).
func tools() []tool { return combinedTools() }

func baseTools() []tool {
	return []tool{
		{Name: "fs_list", ReadOnly: true,
			Description: "List files and directories under a root. Use depth to recurse (default 1).",
			Schema: obj(map[string]any{"root": rootProp(), "path": prop("string", "relative directory, '.' for the root"),
				"depth": prop("integer", "levels to descend, 1-6"), "include_hidden": prop("boolean", "ignored for kb")}, "root"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct {
					Root, Path    string
					Depth         int
					IncludeHidden bool `json:"include_hidden"`
				}
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				if x.Depth < 1 {
					x.Depth = 1
				}
				if x.Depth > 6 {
					x.Depth = 6
				}
				es, err := a.fsys.list(x.Root, x.Path, x.Depth, x.IncludeHidden)
				lf := map[string]any{"root": x.Root, "path": x.Path}
				if err != nil {
					return "", lf, err
				}
				var sb strings.Builder
				for _, e := range es {
					fmt.Fprintf(&sb, "%s\t%d\t%s\t%s\n", e.Type, e.Size, e.MTime, e.Path)
				}
				if sb.Len() == 0 {
					sb.WriteString("(empty)\n")
				}
				return sb.String(), lf, nil
			}},
		{Name: "fs_read", ReadOnly: true,
			Description: "Read a text file (UTF-8). Returns up to 256 KiB per call; use offset to continue.",
			Schema: obj(map[string]any{"root": rootProp(), "path": prop("string", "relative file path"),
				"offset": prop("integer", "byte offset"), "length": prop("integer", "bytes to read, max 262144")}, "root", "path"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct {
					Root, Path     string
					Offset, Length int64
				}
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, more, err := a.fsys.read(x.Root, x.Path, x.Offset, x.Length)
				lf := map[string]any{"root": x.Root, "path": x.Path}
				if err != nil {
					return "", lf, err
				}
				if more {
					s += "\n[more data available; call again with a larger offset]"
				}
				return s, lf, nil
			}},
		{Name: "fs_write",
			Description: "Create, overwrite or append a text file. In kb the previous version is kept automatically (kb_history / kb_restore). Use kb for durable instructions, tmp for scratch files.",
			Schema: obj(map[string]any{"root": rootProp(), "path": prop("string", "relative file path; parent directories are created"),
				"content": prop("string", "UTF-8 text, max 2 MiB per call"),
				"mode":    map[string]any{"type": "string", "enum": []string{"create", "overwrite", "append"}, "description": "create fails if the file exists"}}, "root", "path", "content", "mode"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct{ Root, Path, Content, Mode string }
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				lf := map[string]any{"root": x.Root, "path": x.Path, "mode": x.Mode, "bytes": len(x.Content)}
				s, err := a.fsys.write(x.Root, x.Path, x.Content, x.Mode)
				return s, lf, err
			}},
		{Name: "fs_delete", Destructive: true,
			Description: "Delete a file or an empty directory. In kb a copy is kept in the trash first (kb_history kind=trash, kb_restore).",
			Schema:      obj(map[string]any{"root": rootProp(), "path": prop("string", "relative path")}, "root", "path"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct{ Root, Path string }
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, err := a.fsys.remove(x.Root, x.Path)
				return s, map[string]any{"root": x.Root, "path": x.Path}, err
			}},
		{Name: "fs_move",
			Description: "Move or rename a file inside one root (the destination must not exist).",
			Schema:      obj(map[string]any{"root": rootProp(), "from": prop("string", "source path"), "to": prop("string", "destination path")}, "root", "from", "to"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct{ Root, From, To string }
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				lf := map[string]any{"root": x.Root, "from": x.From, "to": x.To}
				s, _, err := a.fsys.read(x.Root, x.From, 0, maxRead)
				if err != nil {
					return "", lf, err
				}
				if len(s) >= maxRead {
					return "", lf, errors.New("file too large to move with this tool")
				}
				if _, err := a.fsys.write(x.Root, x.To, s, "create"); err != nil {
					return "", lf, err
				}
				if _, err := a.fsys.remove(x.Root, x.From); err != nil {
					return "", lf, err
				}
				return fmt.Sprintf("moved %s:%s -> %s", x.Root, x.From, x.To), lf, nil
			}},
		{Name: "fs_search", ReadOnly: true,
			Description: "Case-insensitive substring search in text files under a root (max 100 matching lines).",
			Schema:      obj(map[string]any{"root": rootProp(), "query": prop("string", "text to find"), "path": prop("string", "relative directory to search, default '.'")}, "root", "query"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x struct{ Root, Query, Path string }
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				if x.Query == "" {
					return "", nil, errors.New("query is empty")
				}
				res, err := a.fsys.search(x.Root, x.Path, x.Query)
				lf := map[string]any{"root": x.Root, "query": x.Query}
				if err != nil {
					return "", lf, err
				}
				if len(res) == 0 {
					return "no matches", lf, nil
				}
				return strings.Join(res, "\n"), lf, nil
			}},
		{Name: "hosts_list", ReadOnly: true,
			Description: "List the SSH hosts this gateway can reach, with descriptions and whether write access is configured.",
			Schema:      obj(map[string]any{}),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				names := make([]string, 0, len(a.cfg.Hosts))
				for n := range a.cfg.Hosts {
					names = append(names, n)
				}
				sort.Strings(names)
				var sb strings.Builder
				for _, n := range names {
					h := a.cfg.Hosts[n]
					fmt.Fprintf(&sb, "%s\t%s:%d\tro_user=%s\twrite=%v\t%s\n", n, h.Addr, h.Port, h.ROUser, h.RWUser != "", h.Desc)
				}
				return sb.String(), nil, nil
			}},
		{Name: "ssh_exec", Destructive: true,
			Description: "Run one command on an allow-listed host over SSH. mode=read (default) uses the read-only account. mode=write uses the admin account and REQUIRES reason and backup_note (what backup/rollback exists); disruptive commands additionally need allow_disruptive=true. Output is capped at 64 KiB; timeout default 60s, max 600s. No interactive input.",
			Schema: obj(map[string]any{
				"host":             prop("string", "host alias from hosts_list"),
				"command":          prop("string", "command line executed by the remote shell"),
				"mode":             map[string]any{"type": "string", "enum": []string{"read", "write"}},
				"timeout_sec":      prop("integer", "1-600"),
				"stdin":            prop("string", "optional text fed to the command's stdin, max 1 MiB"),
				"reason":           prop("string", "write mode: why this change is needed"),
				"backup_note":      prop("string", "write mode: the backup/rollback made before the change"),
				"allow_disruptive": prop("boolean", "write mode: confirm a disruptive command"),
			}, "host", "command"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x execArgs
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				if x.Mode == "" {
					x.Mode = "read"
				}
				lf := map[string]any{"host": x.Host, "mode": x.Mode, "command": x.Command, "stdin_bytes": len(x.Stdin), "reason": x.Reason, "backup_note": x.BackupNote, "disruptive_ok": x.AllowDisruptiv}
				if len(x.Commands) > 0 {
					lf["commands"] = strings.Join(x.Commands, " ;; ")
				}
				if x.Background {
					lf["background"] = true
				}
				if x.LogNode != "" {
					lf["log_node"] = x.LogNode
				}
				s, err := a.sshExec(ctx, x)
				return s, lf, err
			}},
		{Name: "ssh_download", ReadOnly: true,
			Description: "Copy a file from a host (read-only account) into the tmp root, e.g. to back it up or inspect it.",
			Schema: obj(map[string]any{"host": prop("string", "host alias"), "remote_path": prop("string", "absolute or relative remote path"),
				"tmp_path": prop("string", "destination path under the tmp root")}, "host", "remote_path", "tmp_path"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x xferArgs
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, err := a.scp(ctx, x, false)
				return s, map[string]any{"host": x.Host, "remote": x.RemotePath, "tmp": x.TmpPath}, err
			}},
		{Name: "ssh_upload", Destructive: true,
			Description: "Copy a file from the tmp root to a host with the admin account. Requires reason and backup_note. Overwrites the remote file: back it up first.",
			Schema: obj(map[string]any{"host": prop("string", "host alias"), "remote_path": prop("string", "remote destination path"),
				"tmp_path": prop("string", "source path under the tmp root"), "reason": prop("string", "why"), "backup_note": prop("string", "backup/rollback made before")},
				"host", "remote_path", "tmp_path", "reason", "backup_note"),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x xferArgs
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, err := a.scp(ctx, x, true)
				return s, map[string]any{"host": x.Host, "remote": x.RemotePath, "tmp": x.TmpPath, "reason": x.Reason, "backup_note": x.BackupNote}, err
			}},
		{Name: "audit_tail", ReadOnly: true,
			Description: "Newest audit events, one compact line each (full=true: raw JSON). Filters: host, tool, op, errors, since (2h or UTC time), grep.",
			Schema: obj(map[string]any{"lines": prop("integer", "default 30, max 300"), "host": prop("string", "host alias"), "tool": prop("string", "tool or event name"),
				"op": prop("string", "op"), "errors": prop("boolean", "failures only"), "since": prop("string", "90m, 2h or 2026-10-30T12:00"), "grep": prop("string", "regexp over the raw line"), "full": prop("boolean", "raw JSON lines")}),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				var x auditQuery
				if err := decode(raw, &x); err != nil {
					return "", nil, err
				}
				s, err := a.queryAudit(x)
				return s, map[string]any{"lines": x.Lines, "filter_host": x.Host, "filter_tool": x.Tool, "errors_only": x.Errors, "since": x.Since}, err
			}},
		{Name: "server_status", ReadOnly: true,
			Description: "Gateway version, uptime, TLS certificate expiry and number of registered clients/tokens.",
			Schema:      obj(map[string]any{}),
			Run: func(ctx context.Context, a *App, raw json.RawMessage) (string, map[string]any, error) {
				exp := "unknown"
				if t, err := a.certs.notAfter(); err == nil {
					exp = fmt.Sprintf("%s (%d days left)", t.UTC().Format("2006-01-02"), int(time.Until(t).Hours()/24))
				}
				a.st.mu.Lock()
				nc, nt := len(a.st.Clients), len(a.st.Tokens)
				a.st.mu.Unlock()
				return fmt.Sprintf("mcpgw %s\nuptime: %s\ncert expires: %s\nclients: %d, tokens: %d\nhosts: %d", version, time.Since(a.started).Round(time.Second), exp, nc, nt, len(a.cfg.Hosts)), nil, nil
			}},
	}
}
