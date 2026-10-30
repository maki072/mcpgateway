#!/usr/bin/env python3
"""E2E for the SQLite knowledge base, web UI, backups, net policy and CLI (passphrase-only mode)."""
import base64, hashlib, json, os, secrets, ssl, subprocess, sys, tempfile, time, urllib.parse, http.client, re

BIN = os.path.abspath(sys.argv[1])
T = tempfile.mkdtemp(prefix="mcpgw-ui-")
PORT = 18444
BASE = f"https://127.0.0.1:{PORT}"
PASS = "a-long-test-passphrase-123"

def sh(*a): subprocess.run(a, check=True, capture_output=True)
sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{T}/k.pem", "-out", f"{T}/c.pem", "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
salt = os.urandom(16)
json.dump({"salt": salt.hex(), "hash": hashlib.pbkdf2_hmac("sha256", PASS.encode(), salt, 600000, 32).hex(), "iter": 600000}, open(f"{T}/auth.json", "w"))
os.chmod(f"{T}/auth.json", 0o600)

# legacy file-based store to be imported on first start
os.makedirs(f"{T}/kb/old/.x", exist_ok=True); os.makedirs(f"{T}/kb/.history", exist_ok=True)
open(f"{T}/kb/README.md", "w").write("# Legacy readme\nold content xyzzy\n")
open(f"{T}/kb/.history/README.md.20260101T101010.000", "w").write("# Legacy readme\nolder\n")

cfg = {"listen": f"127.0.0.1:{PORT}", "public_url": BASE, "cert_file": f"{T}/c.pem", "key_file": f"{T}/k.pem",
       "kb_dir": f"{T}/kb", "kb_db": f"{T}/kb.db", "backup_dir": f"{T}/backup", "tmp_dir": f"{T}/tmp", "state_file": f"{T}/state.json",
       "auth_file": f"{T}/auth.json", "audit_log": f"{T}/audit.log", "known_hosts": f"{T}/kh",
       "api_cidrs": ["127.0.0.0/8"], "login_cidrs": ["127.0.0.0/8"], "trusted_cidrs": ["127.0.0.0/8"], "net_allow_cidrs": ["10.255.255.0/24"],
       "redirect_allow": ["https://claude.ai/api/mcp/auth_callback"], "hosts": {}}
json.dump(cfg, open(f"{T}/config.json", "w"))
proc = subprocess.Popen([BIN, "-config", f"{T}/config.json"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
ctx = ssl.create_default_context(cafile=f"{T}/c.pem")
fails = 0
def check(name, cond, extra=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(extra)[:300]) if (not cond and extra != "") else ""))
    if not cond: fails += 1

cookie = ""; csrf = ""
def req(method, path, body=None, headers=None, form=None, use_cookie=True, csrf_hdr=True):
    u = urllib.parse.urlparse(BASE + path)
    c = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=60)
    hd = dict(headers or {}); data = None
    if use_cookie and cookie: hd["Cookie"] = cookie
    if method != "GET" and use_cookie and csrf and csrf_hdr and path.startswith("/ui/api/") and "X-CSRF" not in hd: hd["X-CSRF"] = csrf
    if form is not None: data = urllib.parse.urlencode(form); hd["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None: data = json.dumps(body); hd["Content-Type"] = "application/json"
    c.request(method, u.path + ("?" + u.query if u.query else ""), data, hd)
    r = c.getresponse(); b = r.read().decode()
    return r.status, dict(r.getheaders()), b

def ui(method, path, body=None, **kw):
    s, hd, b = req(method, "/ui/api/" + path, body, **kw)
    try: j = json.loads(b)
    except Exception: j = b
    return s, j

try:
    for _ in range(80):
        try: req("GET", "/healthz"); break
        except Exception: time.sleep(0.2)

    # ---- scheduled backup runs at start (no snapshot exists yet)
    ok = False
    for _ in range(50):
        if os.path.isdir(f"{T}/backup") and any(f.startswith("kb-") and f.endswith(".db") for f in os.listdir(f"{T}/backup")) and os.path.exists(f"{T}/backup/export-latest/README.md"): ok = True; break
        time.sleep(0.2)
    check("scheduled backup + export at start", ok)
    check("backup event audited", '"ev":"backup"' in open(f"{T}/audit.log").read() and '"reason":"scheduled"' in open(f"{T}/audit.log").read())

    # ---- UI page + auth
    s, hd, b = req("GET", "/ui/", use_cookie=False)
    nonce = re.search(r"script-src 'nonce-([^']+)'", hd.get("Content-Security-Policy", ""))
    check("ui page + CSP nonce", s == 200 and nonce and nonce.group(1) in b and "{{NONCE}}" not in b and "unsafe-inline" not in hd.get("Content-Security-Policy", ""), hd.get("Content-Security-Policy"))
    s, j = ui("GET", "stats", use_cookie=False); check("api needs session", s == 401)
    s, j = ui("POST", "login", {"pass": "wrong-wrong-wrong-wrong"}, use_cookie=False); check("ui login wrong -> 401", s == 401)
    s, hd, b = req("POST", "/ui/api/login", {"pass": PASS}, use_cookie=False)
    sc = hd.get("Set-Cookie", "")
    check("ui login ok + cookie flags", s == 200 and "HttpOnly" in sc and "Secure" in sc and "SameSite=Strict" in sc, sc)
    cookie = sc.split(";")[0]; csrf = json.loads(b)["csrf"]

    # ---- CSRF / origin
    s, j = ui("PUT", "file", {"root": "kb", "path": "t/a.md", "content": "x", "mode": "create"}, csrf_hdr=False); check("write without csrf rejected", s == 403, (s, j))
    s, j = ui("PUT", "file", {"root": "kb", "path": "t/a.md", "content": "x", "mode": "create"}, headers={"X-CSRF": "bad"}); check("write with bad csrf rejected", s == 403)
    s, j = ui("PUT", "file", {"root": "kb", "path": "t/a.md", "content": "x", "mode": "create"}, headers={"Origin": "https://evil.example"}); check("foreign origin rejected", s == 403)

    # ---- legacy import visible
    s, j = ui("GET", "file?root=kb&path=README.md"); check("legacy file imported", s == 200 and "xyzzy" in j["content"], j)
    s, j = ui("GET", "versions?kind=history&path=README.md"); check("legacy history imported", s == 200 and len(j) == 1, j)

    # ---- CRUD
    doc1 = "---\ntitle: Прокси XR\nsummary: Xray на CT 103\ntags: [xray, proxy]\nupdated: 2026-01-01\n---\n# Прокси XR\nСервер xray, прозрачное проксирование.\n"
    s, j = ui("PUT", "file", {"root": "kb", "path": "projects/home/hosts/xr/card.md", "content": doc1, "mode": "create"}); check("ui create", s == 200, j)
    s, j = ui("PUT", "file", {"root": "kb", "path": "projects/home/hosts/xr/card.md", "content": doc1, "mode": "create"}); check("ui create twice fails", s == 400)
    s, j = ui("GET", "file?root=kb&path=projects/home/hosts/xr/card.md"); mt = j["mtime"]; check("ui read", s == 200 and j["content"] == doc1)
    s, j = ui("PUT", "file", {"root": "kb", "path": "projects/home/hosts/xr/card.md", "content": doc1 + "v2\n", "mode": "overwrite", "expect_mtime": mt}); check("ui overwrite", s == 200, j)
    s, j = ui("PUT", "file", {"root": "kb", "path": "projects/home/hosts/xr/card.md", "content": "stale", "mode": "overwrite", "expect_mtime": mt}); check("stale edit -> 409", s == 409, (s, j))
    s, j = ui("GET", "versions?kind=history&path=projects/home/hosts/xr/card.md"); check("history has 1 version", s == 200 and len(j) == 1, j)
    vid = j[0]["id"]
    s, j = ui("POST", "restore", {"id": vid}); check("restore", s == 200, j)
    s, j = ui("GET", "file?root=kb&path=projects/home/hosts/xr/card.md"); check("restored content", j["content"] == doc1)
    s, j = ui("GET", "list?root=kb&path=projects/home"); check("list implied dirs", s == 200 and any(e["path"] == "projects/home/hosts" and e["type"] == "dir" for e in j), j)
    s, j = ui("POST", "mkdir", {"root": "kb", "path": "projects/empty"}); check("mkdir", s == 200)
    s, j = ui("GET", "list?root=kb&path=projects"); check("explicit dir listed", any(e["path"] == "projects/empty" for e in j), j)
    s, j = ui("POST", "move", {"root": "kb", "from": "projects/home/hosts/xr/card.md", "to": "projects/home/hosts/xr2/card.md"}); check("move", s == 200, j)
    s, j = ui("PUT", "file", {"root": "kb", "path": "projects/home/hosts/xr2/card.md/x", "content": "x", "mode": "create"}); check("file-as-dir conflict", s == 400, j)
    s, j = ui("PUT", "file", {"root": "kb", "path": "../evil", "content": "x", "mode": "create"}); check("traversal rejected", s == 400)
    s, j = ui("PUT", "file", {"root": "kb", "path": "n.md", "content": "a\x00b", "mode": "create"}); check("NUL rejected", s == 400)
    s, j = ui("DELETE", "file?root=kb&path=projects/home/hosts/xr2/card.md"); check("delete", s == 200, j)
    s, j = ui("GET", "versions?kind=trash"); check("trash has note", s == 200 and any(v["path"] == "projects/home/hosts/xr2/card.md" for v in j), j)
    tid = [v for v in j if v["path"].endswith("xr2/card.md")][0]["id"]
    s, j = ui("POST", "restore", {"id": tid}); check("restore from trash", s == 200, j)
    s, j = ui("DELETE", "file?root=kb&path=projects/empty"); check("delete empty dir", s == 200, j)
    s, j = ui("DELETE", "file?root=kb&path=projects/home"); check("non-empty dir refused", s == 400, j)

    # ---- search (FTS, Cyrillic, prefix)
    s, j = ui("GET", "search?" + urllib.parse.urlencode({"q": "прозрачное прокс"})); check("search cyrillic prefix", s == 200 and "xr2/card.md" in j["text"], j)
    s, j = ui("GET", "search?" + urllib.parse.urlencode({"q": "xray", "tags": "proxy"})); check("search tag filter", "xr2/card.md" in j["text"], j)
    s, j = ui("GET", "search?" + urllib.parse.urlencode({"q": "ray"})); check("substring fallback", "xr2/card.md" in j["text"], j)
    s, j = ui("GET", "index"); check("index line", "Прокси XR" in j["text"] and "[xray,proxy]" in j["text"], j)

    # ---- stats + backups
    s, j = ui("GET", "stats"); check("stats", s == 200 and j["notes"] >= 2 and "audit" in j and j["audit"].get("tools") is not None and j["kb"]["history_files"] >= 1, j)
    s, j = ui("POST", "backups"); check("backup now", s == 200 and j["name"].startswith("kb-") and j["sha256"], j)
    time.sleep(1.1)
    s, j = ui("GET", "backups"); check("backup listed", s == 200 and len(j["snapshots"]) >= 1, j)
    check("export-latest written", os.path.exists(f"{T}/backup/export-latest/projects/home/hosts/xr2/card.md"))
    s, j = ui("GET", "audit?lines=20"); check("audit via ui", s == 200 and len(j["lines"]) > 0)

    # ---- MCP side (oauth with passphrase only)
    verifier = secrets.token_urlsafe(48); chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    redir = "https://claude.ai/api/mcp/auth_callback"
    s, _, b = req("POST", "/register", {"client_name": "Claude", "redirect_uris": [redir]}, use_cookie=False); cid = json.loads(b)["client_id"]
    qs = urllib.parse.urlencode({"response_type": "code", "client_id": cid, "redirect_uri": redir, "state": "s", "code_challenge": chal, "code_challenge_method": "S256"})
    s, _, page = req("GET", "/authorize?" + qs, use_cookie=False)
    check("login page has no totp field", s == 200 and 'name="totp"' not in page)
    rid = page.split('name="rid" value="')[1].split('"')[0]
    s, hd, _ = req("POST", "/authorize", form={"rid": rid, "pass": PASS}, use_cookie=False)
    code = urllib.parse.parse_qs(urllib.parse.urlparse(hd["Location"]).query)["code"][0]
    s, _, b = req("POST", "/token", form={"grant_type": "authorization_code", "code": code, "code_verifier": verifier, "client_id": cid, "redirect_uri": redir}, use_cookie=False)
    AT = json.loads(b)["access_token"]
    n = [0]
    def call(name, args):
        n[0] += 1
        s, _, b = req("POST", "/mcp", {"jsonrpc": "2.0", "id": n[0], "method": "tools/call", "params": {"name": name, "arguments": args}}, {"Authorization": "Bearer " + AT}, use_cookie=False)
        r = json.loads(b)["result"]; return r.get("isError", False), r["content"][0]["text"]
    s, _, b = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 99, "method": "tools/list"}, {"Authorization": "Bearer " + AT}, use_cookie=False)
    names = {t["name"] for t in json.loads(b)["result"]["tools"]}
    check("tools registered", {"kb", "fs", "ssh", "net", "status"} == names, names)

    e, t = call("kb_find", {"query": "xray прокси"}); check("kb_find tool", not e and "xr2/card.md" in t and "L" in t, t)
    e, t = call("kb_log", {"node": "projects/home/hosts/xr2", "entry": "Changed X; backup: Y"}); check("kb_log", not e and "log/" in t, t)
    e, t = call("kb_log", {"node": "projects/nope", "entry": "x"}); check("kb_log needs card", e, t)
    e, t = call("fs_read", {"root": "kb", "path": "projects/home/hosts/xr2/card.md"}); check("kb_log refreshed 'updated'", re.search(r"updated: 20\d\d-\d\d-\d\d", t) and "updated: 2026-01-01" not in t, t[:200])
    e, t = call("kb_index", {}); check("kb_index hides logs", not e and "/log/" not in t, t)
    e, t = call("kb_index", {"include_logs": True}); check("kb_index include logs", "/log/" in t, t)
    e, t = call("kb_history", {"path": "projects/home/hosts/xr2/card.md"}); check("kb_history list", not e and "id=" in t, t)

    # ---- net policy
    e, t = call("net_http", {"url": "http://127.0.0.1:%d/" % PORT}); check("net: loopback denied", e and "not allowed" in t, t)
    e, t = call("net_tcp", {"host": "127.0.0.1", "port": PORT}); check("net: tcp loopback denied", "not allowed" in t, t)
    e, t = call("net_http", {"url": "http://192.168.55.1:8080/"}); check("net: outside allow list denied", e and "outside net_allow_cidrs" in t, t)
    e, t = call("net_tcp", {"host": "8.8.8.8", "port": 53}); check("net: public tcp/53 denied", "outside net_allow_cidrs" in t, t)
    e, t = call("net_http", {"url": "http://10.255.255.1/", "timeout_sec": 2}); check("net: allowed cidr passes policy", "outside net_allow_cidrs" not in t and "not allowed" not in t, t)
    e, t = call("net_http", {"url": "http://10.255.255.1/", "method": "POST"}); check("net: POST needs write", e and "mode=write" in t, t)
    e, t = call("net_http", {"url": "http://user:pw@10.255.255.1/"}); check("net: credentials in url rejected", e, t)
    e, t = call("net_tcp", {"host": "10.255.255.1", "port": 80, "send": "x"}); check("net: tcp payload needs write", e and "mode=write" in t, t)
    e, t = call("net_udp", {"host": "10.255.255.1", "port": 53, "send": "x"}); check("net: udp needs write", e, t)
    e, t = call("net_udp", {"host": "10.255.255.1", "port": 53, "send": "x", "mode": "write", "reason": "short", "backup_note": "x"}); check("net: udp needs real reason", e and "10 characters" in t, t)
    e, t = call("net_dns", {"name": "localhost"}); check("net_dns", not e and "127.0.0.1" in t, t)

finally:
    proc.terminate()
    try: out = proc.communicate(timeout=10)[0].decode()
    except Exception: proc.kill(); out = ""
    print("---- server log (tail) ----"); print("\n".join(out.splitlines()[-8:]))

# ---- CLI: backup / list / restore / export on the stopped service
def cli(*a):
    r = subprocess.run([BIN, *a, "-config", f"{T}/config.json"], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr
rc, o = cli("kb-backup"); check("cli kb-backup", rc == 0 and "snapshot kb-" in o, o)
rc, o = cli("kb-list"); lines = [l for l in o.splitlines() if l.startswith("kb-")]; check("cli kb-list", rc == 0 and len(lines) >= 2, o)
oldest = lines[-1].split("\t")[0]
rc, o = cli("kb-restore", "-file", f"{T}/backup/{oldest}"); check("cli restore needs -yes", rc != 0)
open(f"{T}/backup/{oldest}", "ab").write(b"tamper")
rc, o = cli("kb-restore", "-file", f"{T}/backup/{oldest}", "-yes"); check("cli restore rejects tampered snapshot", rc != 0, o)
newest = lines[0].split("\t")[0]
rc, o = cli("kb-restore", "-file", f"{T}/backup/{newest}", "-yes"); check("cli restore ok", rc == 0 and "before-restore" in o, o)
rc, o = cli("kb-export", "-dir", f"{T}/exp"); check("cli export", rc == 0 and os.path.exists(f"{T}/exp/projects/home/hosts/xr2/card.md") and os.path.exists(f"{T}/exp/README.md"), o)

print(f"\nFAILS: {fails}")
sys.exit(1 if fails else 0)
