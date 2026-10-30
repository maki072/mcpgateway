#!/usr/bin/env python3
"""End-to-end test for mcpgw against a local instance (self-signed TLS, fake ssh)."""
import base64, hashlib, hmac, json, os, secrets, ssl, struct, subprocess, sys, tempfile, time, urllib.parse, urllib.request, http.client

BIN = sys.argv[1]
T = tempfile.mkdtemp(prefix="mcpgw-test-")
PORT = 18443
BASE = f"https://127.0.0.1:{PORT}"

def sh(*a): subprocess.run(a, check=True, capture_output=True)

# self-signed cert
sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{T}/k.pem", "-out", f"{T}/c.pem",
   "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")

# auth file (same format as `mcpgw setup`)
salt = os.urandom(16); PASS = "correct horse battery staple"
h = hashlib.pbkdf2_hmac("sha256", PASS.encode(), salt, 600000, 32).hex()
sec = os.urandom(20); b32 = base64.b32encode(sec).decode().rstrip("=")
json.dump({"salt": salt.hex(), "hash": h, "iter": 600000, "totp_secret": b32}, open(f"{T}/auth.json", "w"))
os.chmod(f"{T}/auth.json", 0o600)

def totp(step):
    d = hmac.new(sec, struct.pack(">Q", step), hashlib.sha1).digest()
    o = d[-1] & 15
    return "%06d" % ((struct.unpack(">I", d[o:o+4])[0] & 0x7fffffff) % 1000000)

# fake ssh/scp: prints its arguments so we can assert on them
open(f"{T}/fakessh", "w").write('#!/bin/sh\necho "ARGS: $@"\nexit 3\n'); os.chmod(f"{T}/fakessh", 0o755)
cfg = {"listen": f"127.0.0.1:{PORT}", "public_url": BASE, "cert_file": f"{T}/c.pem", "key_file": f"{T}/k.pem",
       "kb_dir": f"{T}/kb", "kb_db": f"{T}/kb.db", "backup_dir": f"{T}/backup", "net_allow_cidrs": ["10.255.255.0/24"], "tmp_dir": f"{T}/tmp", "state_file": f"{T}/state.json", "auth_file": f"{T}/auth.json",
       "audit_log": f"{T}/audit.log", "known_hosts": f"{T}/kh", "ssh_bin": f"{T}/fakessh", "scp_bin": f"{T}/fakessh",
       "api_cidrs": ["127.0.0.0/8"], "login_cidrs": ["127.0.0.0/8"], "trusted_cidrs": ["127.0.0.0/8"], "trusted_skip_totp": False,
       "redirect_allow": ["https://claude.ai/api/mcp/auth_callback"], "allow_loopback": True,
       "hosts": {"pve": {"addr": "192.0.2.1", "group": "g1", "desc": "test", "ro_user": "mcp-ro", "ro_key": "/k/ro", "rw_user": "root", "rw_key": "/k/rw"},
                 "ro": {"addr": "192.0.2.2", "group": "g2", "desc": "ro only", "ro_user": "u", "ro_key": "/k/ro"}}}
json.dump(cfg, open(f"{T}/config.json", "w"))
proc = subprocess.Popen([BIN, "-config", f"{T}/config.json"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
ctx = ssl.create_default_context(cafile=f"{T}/c.pem")
fails = 0
def check(name, cond, extra=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(extra)) if (not cond and extra) else ""))
    if not cond: fails += 1

def req(method, path, body=None, headers=None, form=None, follow=False):
    u = urllib.parse.urlparse(BASE + path)
    c = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=30)
    hd = dict(headers or {}); data = None
    if form is not None: data = urllib.parse.urlencode(form); hd["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None: data = json.dumps(body); hd["Content-Type"] = "application/json"
    c.request(method, u.path + ("?" + u.query if u.query else ""), data, hd)
    r = c.getresponse(); b = r.read().decode()
    return r.status, dict(r.getheaders()), b

try:
    for _ in range(50):
        try: req("GET", "/healthz"); break
        except Exception: time.sleep(0.2)

    s, hd, _ = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    check("mcp without token -> 401 + resource_metadata", s == 401 and "resource_metadata" in hd.get("Www-Authenticate", ""), (s, hd))
    s, _, b = req("GET", "/.well-known/oauth-protected-resource/mcp")
    check("protected resource metadata", s == 200 and json.loads(b)["resource"] == BASE + "/mcp")
    s, _, b = req("GET", "/.well-known/oauth-authorization-server")
    m = json.loads(b); check("AS metadata S256 + DCR", m["code_challenge_methods_supported"] == ["S256"] and "registration_endpoint" in m)

    s, _, b = req("POST", "/register", {"client_name": "evil", "redirect_uris": ["https://evil.example/cb"]})
    check("DCR rejects foreign redirect", s == 400, b)
    s, _, b = req("POST", "/register", {"client_name": "Claude", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]})
    cid = json.loads(b)["client_id"]; check("DCR ok", s == 201)

    verifier = secrets.token_urlsafe(48)
    chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    redir = "https://claude.ai/api/mcp/auth_callback"
    qs = urllib.parse.urlencode({"response_type": "code", "client_id": cid, "redirect_uri": redir, "state": "xyz", "code_challenge": chal, "code_challenge_method": "S256"})
    s, _, page = req("GET", "/authorize?" + qs)
    check("authorize page", s == 200 and 'name="rid"' in page)
    rid = page.split('name="rid" value="')[1].split('"')[0]
    s, _, _ = req("GET", "/authorize?" + qs.replace("S256", "plain"))
    check("authorize requires S256", s == 400)
    s, _, _ = req("GET", "/authorize?" + qs.replace("claude.ai", "evil.example"))
    check("authorize rejects unregistered redirect", s == 400)

    s, _, _ = req("POST", "/authorize", form={"rid": rid, "pass": "wrong", "totp": "000000"})
    check("login wrong creds -> 401", s == 401)
    step = int(time.time()) // 30
    s, hd, _ = req("POST", "/authorize", form={"rid": rid, "pass": PASS, "totp": totp(step)})
    loc = hd.get("Location", "")
    check("login ok -> 302 with code+state", s == 302 and loc.startswith(redir) and "state=xyz" in loc, (s, loc))
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]

    s, _, b = req("POST", "/token", form={"grant_type": "authorization_code", "code": code, "client_id": cid, "redirect_uri": redir, "code_verifier": "x" * 50})
    check("token with bad verifier rejected", s == 400)
    s, _, b = req("POST", "/token", form={"grant_type": "authorization_code", "code": code, "client_id": cid, "redirect_uri": redir, "code_verifier": verifier})
    check("code is single use (after failed attempt)", s == 400)

    # new flow, this time valid (TOTP of the same step is replay-protected -> use the next step)
    s, _, page = req("GET", "/authorize?" + qs); rid = page.split('name="rid" value="')[1].split('"')[0]
    s, _, _ = req("POST", "/authorize", form={"rid": rid, "pass": PASS, "totp": totp(step)})
    check("TOTP replay rejected", s == 401)
    s, hd, _ = req("POST", "/authorize", form={"rid": rid, "pass": PASS, "totp": totp(step + 1)})
    code = urllib.parse.parse_qs(urllib.parse.urlparse(hd["Location"]).query)["code"][0]
    s, _, b = req("POST", "/token", form={"grant_type": "authorization_code", "code": code, "client_id": cid, "redirect_uri": redir, "code_verifier": verifier})
    tok = json.loads(b); check("token exchange", s == 200 and tok["token_type"] == "Bearer" and tok["refresh_token"])
    A = {"Authorization": "Bearer " + tok["access_token"]}

    def call(name, args=None):
        s, _, b = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}, A)
        r = json.loads(b)["result"]; return r.get("isError", False), r["content"][0]["text"]

    s, _, b = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, A)
    check("initialize", s == 200 and json.loads(b)["result"]["protocolVersion"] == "2025-06-18")
    s, _, b = req("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, A)
    check("notification -> 202", s == 202)
    s, _, b = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, A)
    names = [t["name"] for t in json.loads(b)["result"]["tools"]]
    check("tools/list: only combined tools", set(names) == {"kb", "fs", "ssh", "net", "status"}, names)
    sz = len(json.dumps(json.loads(b)["result"]["tools"]))
    check("tools/list payload under 9 KB", sz < 9000, sz)
    s, _, b = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, A)
    check("instructions start with kb find", "kb op=find" in json.loads(b)["result"]["instructions"])

    e, t = call("fs_write", {"root": "kb", "path": "projects/home.md", "content": "v1", "mode": "create"}); check("kb create", not e, t)
    e, t = call("fs_write", {"root": "kb", "path": "projects/home.md", "content": "v1", "mode": "create"}); check("kb create twice fails", e)
    e, t = call("fs_write", {"root": "kb", "path": "projects/home.md", "content": "v2", "mode": "overwrite"}); check("kb overwrite", not e, t)
    e, t = call("fs_write", {"root": "kb", "path": "projects/home.md", "content": "+v3", "mode": "append"}); check("kb append", not e, t)
    e, t = call("fs_read", {"root": "kb", "path": "projects/home.md"}); check("kb read", t == "v2+v3", t)
    e, t = call("fs_list", {"root": "kb", "path": ".", "depth": 3, "include_hidden": True}); check("kb listed", "projects" in t, t)
    e, t = call("kb_history", {"path": "projects/home.md"}); check("history kept (v1 and v2)", not e and t.count("id=") == 2, t)
    e, t = call("fs_search", {"root": "kb", "query": "V2"}); check("search", "home.md:1" in t, t)
    for bad in ["../x", "/etc/passwd", "a/../../x", ".history/x", "a\\b"]:
        e, t = call("fs_write", {"root": "kb", "path": bad, "content": "x", "mode": "create"}); check("path rejected: " + bad, e, t)
    e, t = call("fs_read", {"root": "kb", "path": "../../etc/passwd"}); check("read traversal rejected", e, t)
    os.makedirs(f"{T}/tmp", exist_ok=True); os.symlink("/etc", f"{T}/tmp/link")
    e, t = call("fs_read", {"root": "tmp", "path": "link/passwd"}); check("tmp symlink escape blocked", e, t)
    e, t = call("fs_delete", {"root": "kb", "path": "projects/home.md"}); check("kb delete", not e and "trash" in t, t)
    e, t = call("kb_history", {"kind": "trash"}); check("trash copy exists", not e and "projects/home.md" in t, t)
    e, t = call("fs_write", {"root": "tmp", "path": "n.txt", "content": "tmp", "mode": "create"}); check("tmp write", not e, t)
    e, t = call("fs_move", {"root": "tmp", "from": "n.txt", "to": "d/m.txt"}); check("tmp move", not e, t)

    # combined tools
    doc = "---\ntitle: Big\nsummary: s\n---\n# Big\nintro\n## Alpha\nalpha text\n## Beta\nbeta text\n"
    e, t = call("fs", {"op": "write", "root": "kb", "path": "p/x/card.md", "content": doc, "mode": "create"}); check("fs write (combined)", not e, t)
    e, t = call("fs", {"op": "write", "root": "kb", "path": "p/x/docs/long.md", "content": doc, "mode": "create"}); check("fs write docs note", not e, t)
    e, t = call("fs", {"op": "toc", "root": "kb", "path": "p/x/card.md"}); check("fs toc", not e and "L7 ## Alpha" in t and "## Beta" in t, t)
    e, t = call("fs", {"op": "read", "root": "kb", "path": "p/x/card.md", "section": "beta"}); check("fs read section", not e and t == "## Beta\nbeta text\n", t)
    e, t = call("fs", {"op": "read", "root": "kb", "path": "p/x/card.md", "section": "gamma"}); check("fs read missing section", e, t)
    e, t = call("kb", {"op": "index", "path": "p"}); check("kb index hides docs/", not e and "p/x/card.md" in t and "long.md" not in t and "1 docs/ notes hidden" in t, t)
    e, t = call("kb", {"op": "index", "path": "p", "include_docs": True}); check("kb index include_docs", not e and "long.md" in t, t)
    e, t = call("kb", {"op": "find", "query": "alpha"}); check("kb find (combined)", not e and "p/x/card.md" in t, t)
    e, t = call("kb", {"op": "nope"}); check("unknown op rejected with list", e and "find" in t, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "uptime", "grep": "StrictHost"}); check("ssh exec grep (combined)", not e and "StrictHostKeyChecking=yes" in t and "lines shown" not in t or "of" in t, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "uptime", "grep": "("}); check("ssh exec bad grep rejected", e, t)
    e, t = call("ssh", {"op": "hosts"}); check("ssh hosts (combined)", not e and "pve" in t, t)
    e, t = call("status", {"op": "server"}); check("status server", not e and "mcpgw" in t, t)
    e, t = call("status", {"op": "audit", "lines": 3}); check("status audit", not e and t.count("\n") <= 3, t)
    e, t = call("net", {"op": "dns", "name": "localhost"}); check("net dns routed", not e and "127.0.0.1" in t, t)
    e, t = call("fs", {"op": "delete", "root": "kb", "path": "p/x/docs/long.md"}); check("fs delete (combined)", not e, t)
    e, t = call("hosts_list"); check("legacy name still works", "pve" in t, t)
    e, t = call("hosts_list"); check("hosts_list", "pve" in t and "write=true" in t, t)
    e, t = call("ssh_exec", {"host": "pve", "command": "uptime"}); check("ssh read uses ro user + hardened opts", "mcp-ro@192.0.2.1" in t and "StrictHostKeyChecking=yes" in t and "exit 3" in t and "/k/ro" in t, t)
    e, t = call("ssh_exec", {"host": "pve", "command": "touch /x", "mode": "write"}); check("write needs reason/backup", e, t)
    e, t = call("ssh_exec", {"host": "pve", "command": "systemctl restart xray", "mode": "write", "reason": "apply config change", "backup_note": "copied config to tmp"}); check("disruptive blocked", e and "disruptive" in t, t)
    e, t = call("ssh_exec", {"host": "pve", "command": "touch /x", "mode": "write", "reason": "create marker file", "backup_note": "file did not exist before"}); check("write ok uses rw user", not e and "root@192.0.2.1" in t and "/k/rw" in t, t)
    e, t = call("ssh_exec", {"host": "ro", "command": "touch /x", "mode": "write", "reason": "create marker file", "backup_note": "file did not exist before"}); check("write refused on ro-only host", e, t)
    e, t = call("ssh_exec", {"host": "nope", "command": "id"}); check("unknown host refused", e, t)
    e, t = call("ssh_download", {"host": "pve", "remote_path": "/etc/hostname", "tmp_path": "dl/hostname"}); check("download builds scp (fake exits 3 -> error)", e and "scp failed" in t, t)
    e, t = call("ssh_download", {"host": "pve", "remote_path": "-oProxyCommand=x", "tmp_path": "dl/h"}); check("download rejects option-like path", e, t)
    e, t = call("ssh_upload", {"host": "pve", "remote_path": "/tmp/x", "tmp_path": "d/m.txt"}); check("upload needs reason", e, t)
    e, t = call("audit_tail", {"lines": 5}); check("audit_tail compact", "ssh_exec" in t and '"ev"' not in t, t)
    e, t = call("audit_tail", {"lines": 5, "full": True}); check("audit_tail full", '"ev":"tool"' in t, t)
    # v0.2: gateway-side pipeline in read mode (fake ssh prints its arguments)
    e, t = call("ssh_exec", {"host": "pve", "command": "cat /etc/hosts | grep -c ARGS"}); check("read pipeline: remote gets only the first command", not e and t.startswith("exit 3\n1"), t)
    e, t = call("ssh_exec", {"host": "pve", "command": "cat /etc/hosts | grep ARGS | head -1"}); check("read pipeline: filters applied", not e and "cat /etc/hosts" in t and "grep" not in t.split("\n")[1], t)
    e, t = call("ssh_exec", {"host": "pve", "command": "cat /etc/hosts | cut -c1-9"}); check("read pipeline: unknown filter goes to the host unchanged", not e and "| cut -c1-9" in t, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "commands": ["uptime", "hostname"]}); check("batch", not e and "### [1] uptime" in t and "### [2] hostname" in t, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "echo password=Sup3rSecretVal"}); check("output masked", "Sup3rSecretVal" not in t and "password=***" in t, t)
    e, t = call("audit_tail", {"lines": 50, "full": True}); check("audit masked", "Sup3rSecretVal" not in t, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "uptime", "background": True}); check("background start", not e and "job j" in t, t)

    jid = t.split("job ")[1].split(" ")[0] if not e else ""
    for _ in range(30):
        e, t = call("ssh", {"op": "job", "id": jid})
        if "done in" in t or e: break
        time.sleep(0.3)
    check("background result", not e and "done in" in t and "ARGS" in t, t)

    # v0.2.3: multi-host, change window, usage, one-time upload link, archive import
    e, t = call("ssh", {"op": "exec", "hosts": ["pve", "ro"], "command": "uptime"}); check("multi-host read", not e and t.startswith("2 hosts:") and "pve" in t and "ro" in t, t)
    e, t = call("ssh", {"op": "exec", "hosts": ["@g1"], "command": "uptime"}); check("multi-host group", not e and t.startswith("1 hosts:"), t)
    e, t = call("ssh", {"op": "exec", "hosts": ["*"], "command": "touch /x", "mode": "write", "reason": "create marker file", "backup_note": "file did not exist before"}); check("star refused in write mode", e, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "hosts": ["ro"], "command": "uptime"}); check("host and hosts together refused", e, t)
    e, t = call("ssh", {"op": "window", "reason": "short change series", "backup_note": "copies made on each host", "hosts": ["pve"], "minutes": 5}); check("window opens", not e and "window w-" in t, t)
    wid = t.split("window ")[1].split()[0] if not e else ""
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "touch /x", "mode": "write", "window": wid}); check("write via window", not e and "root@192.0.2.1" in t, t)
    e, t = call("ssh", {"op": "exec", "host": "ro", "command": "touch /x", "mode": "write", "window": wid}); check("window scope enforced", e and "outside the scope" in t, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "uptime", "window": wid}); check("window needs write mode", e, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "systemctl restart x", "mode": "write", "window": wid}); check("window does not lift disruptive check", e and "disruptive" in t, t)
    e, t = call("ssh", {"op": "window", "id": wid, "close": True}); check("window closes", not e and "closed" in t, t)
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "touch /x", "mode": "write", "window": wid}); check("closed window refused", e, t)
    e, t = call("status", {"op": "usage", "since": "1h"}); check("usage report", not e and "tool calls since 1h" in t and "ssh/exec" in t, t)

    import tarfile, io
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (("n/one.md", b"# One\nhello\n"), ("n/sec.md", b"password=Sup3rSecretVal\n"), (".hidden/x.md", b"x\n")):
            ti = tarfile.TarInfo(name); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
    e, t = call("fs", {"op": "upload_url", "root": "tmp", "name": "in/n.tgz", "max_mb": 1}); check("upload_url", not e and "/up/" in t, t)
    upath = "/up/" + t.split("/up/")[1].split()[0] if not e else "/up/x"
    c = http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx, timeout=30)
    c.request("PUT", upath, buf.getvalue()); r_ = c.getresponse(); body_ = r_.read().decode()
    check("upload stored", r_.status == 200 and "stored tmp:in/n.tgz" in body_, (r_.status, body_))
    c = http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx, timeout=30)
    c.request("PUT", upath, b"again"); r_ = c.getresponse(); r_.read()
    check("upload link is single-use", r_.status == 404, r_.status)
    c = http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx, timeout=30)
    c.request("GET", upath); r_ = c.getresponse(); r_.read()
    check("upload rejects GET", r_.status in (404, 405), r_.status)
    e, t = call("fs", {"op": "import", "root": "tmp", "tmp_path": "in/n.tgz", "prefix": "imp"}); check("import skips secrets and hidden", not e and "imported 1 notes" in t and "1 with secrets" in t, t)
    e, t = call("fs", {"op": "read", "root": "kb", "path": "imp/n/one.md"}); check("imported note readable", not e and "hello" in t, t)
    e, t = call("fs", {"op": "import", "root": "tmp", "tmp_path": "in/n.tgz", "prefix": "imp", "redact": True}); check("import redact masks secret", not e and "imported 1 notes" in t and "1 existing" in t, t)
    e, t = call("fs", {"op": "read", "root": "kb", "path": "imp/n/sec.md"}); check("redacted note has no secret", not e and "Sup3rSecretVal" not in t, t)
    e, t = call("ssh", {"op": "job"}); check("job list", jid in t, t)
    e, t = call("fs_write", {"root": "kb", "path": "projects/t/card.md", "content": "---\ntitle: T\nupdated: 2026-01-01\n---\n# T\n## A\none\n\n## B\ntwo\n", "mode": "create"})
    e, t = call("ssh", {"op": "exec", "host": "pve", "command": "touch /x", "mode": "write", "reason": "create marker file", "backup_note": "nothing to back up, test", "log_node": "projects/t"})
    check("log_node writes kb log", "logged to kb:projects/t/log/" in t, t)
    e, t = call("kb", {"op": "find", "query": "marker", "include_logs": True}); check("log entry findable", "projects/t/log/" in t, t)
    e, t = call("fs", {"op": "patch", "root": "kb", "path": "projects/t/card.md", "old": "one", "new": "ONE"}); check("fs patch", not e and "1 replacement" in t, t)
    e, t = call("fs", {"op": "patch", "root": "kb", "path": "projects/t/card.md", "old": "absent", "new": "x"}); check("fs patch missing", e, t)
    e, t = call("fs", {"op": "append_section", "root": "kb", "path": "projects/t/card.md", "section": "A", "content": "added"}); check("fs append_section", not e, t)
    e, t = call("fs_read", {"root": "kb", "path": "projects/t/card.md"}); check("patched content", "## A\nONE\nadded\n\n## B" in t, t)
    e, t = call("status", {"op": "audit", "errors": True, "lines": 5}); check("audit errors filter", "FAIL" in t and all(("FAIL" in l or "fail" in l or "reject" in l or "locked" in l) for l in t.split("\n")), t)
    e, t = call("status", {"op": "audit", "tool": "fs", "filter_op": "patch"}); check("audit tool/op filter", "fs/patch" in t and "ssh" not in t, t)
    e, t = call("server_status"); check("server_status", "mcpgw" in t, t)

    s, _, b = req("POST", "/token", form={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": cid})
    r2 = json.loads(b); check("refresh rotates", s == 200 and r2["refresh_token"] != tok["refresh_token"])
    s, _, b = req("POST", "/token", form={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"], "client_id": cid})
    check("refresh reuse rejected", s == 400)
    s, _, b = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"Authorization": "Bearer " + r2["access_token"]})
    check("family revoked after reuse", s == 401)

    # lockout: 5 failures lock the login
    s, _, page = req("GET", "/authorize?" + qs); rid = page.split('name="rid" value="')[1].split('"')[0]
    for _ in range(5): req("POST", "/authorize", form={"rid": rid, "pass": "bad", "totp": "111111"})
    s, _, _ = req("POST", "/authorize", form={"rid": rid, "pass": PASS, "totp": totp(step + 2)})
    check("spent login request after 5 tries", s == 400, s)
    s, _, page = req("GET", "/authorize?" + qs); rid = page.split('name="rid" value="')[1].split('"')[0]
    s, _, _ = req("POST", "/authorize", form={"rid": rid, "pass": PASS, "totp": totp(step + 2)})
    check("lockout after repeated failures", s == 429, s)

    st = os.stat(f"{T}/state.json").st_mode & 0o777; check("state file mode 0600", st == 0o600, oct(st))
    audit = open(f"{T}/audit.log").read()
    check("audit has no secrets", PASS not in audit and tok["access_token"] not in audit and tok["refresh_token"] not in audit)
finally:
    proc.terminate()
    try: out = proc.communicate(timeout=5)[0].decode()
    except Exception: out = ""
    if fails: print(out[-1500:])
print("FAILS:", fails)
sys.exit(1 if fails else 0)
