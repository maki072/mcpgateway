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
       "kb_dir": f"{T}/kb", "tmp_dir": f"{T}/tmp", "state_file": f"{T}/state.json", "auth_file": f"{T}/auth.json",
       "audit_log": f"{T}/audit.log", "known_hosts": f"{T}/kh", "ssh_bin": f"{T}/fakessh", "scp_bin": f"{T}/fakessh",
       "api_cidrs": ["127.0.0.0/8"], "login_cidrs": ["127.0.0.0/8"],
       "redirect_allow": ["https://claude.ai/api/mcp/auth_callback"], "allow_loopback": True,
       "hosts": {"pve": {"addr": "192.0.2.1", "desc": "test", "ro_user": "mcp-ro", "ro_key": "/k/ro", "rw_user": "root", "rw_key": "/k/rw"},
                 "ro": {"addr": "192.0.2.2", "desc": "ro only", "ro_user": "u", "ro_key": "/k/ro"}}}
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
    check("tools/list", {"fs_read", "fs_write", "ssh_exec", "ssh_upload", "ssh_download"} <= set(names), names)

    e, t = call("fs_write", {"root": "kb", "path": "projects/home.md", "content": "v1", "mode": "create"}); check("kb create", not e, t)
    e, t = call("fs_write", {"root": "kb", "path": "projects/home.md", "content": "v1", "mode": "create"}); check("kb create twice fails", e)
    e, t = call("fs_write", {"root": "kb", "path": "projects/home.md", "content": "v2", "mode": "overwrite"}); check("kb overwrite", not e, t)
    e, t = call("fs_write", {"root": "kb", "path": "projects/home.md", "content": "+v3", "mode": "append"}); check("kb append", not e, t)
    e, t = call("fs_read", {"root": "kb", "path": "projects/home.md"}); check("kb read", t == "v2+v3", t)
    e, t = call("fs_list", {"root": "kb", "path": ".", "depth": 3, "include_hidden": True}); check("history kept", ".history/projects__home.md." in t, t)
    e, t = call("fs_search", {"root": "kb", "query": "V2"}); check("search", "home.md:1" in t, t)
    for bad in ["../x", "/etc/passwd", "a/../../x", ".history/x", "a\\b"]:
        e, t = call("fs_write", {"root": "kb", "path": bad, "content": "x", "mode": "create"}); check("path rejected: " + bad, e, t)
    e, t = call("fs_read", {"root": "kb", "path": "../../etc/passwd"}); check("read traversal rejected", e, t)
    os.symlink("/etc", f"{T}/kb/link")
    e, t = call("fs_read", {"root": "kb", "path": "link/passwd"}); check("symlink escape blocked", e, t)
    e, t = call("fs_delete", {"root": "kb", "path": "projects/home.md"}); check("kb delete", not e and ".trash" in t, t)
    e, t = call("fs_list", {"root": "kb", "include_hidden": True, "depth": 3}); check("trash copy exists", ".trash/projects__home.md." in t, t)
    e, t = call("fs_write", {"root": "tmp", "path": "n.txt", "content": "tmp", "mode": "create"}); check("tmp write", not e, t)
    e, t = call("fs_move", {"root": "tmp", "from": "n.txt", "to": "d/m.txt"}); check("tmp move", not e, t)

    e, t = call("hosts_list"); check("hosts_list", "pve" in t and "write=true" in t, t)
    e, t = call("ssh_exec", {"host": "pve", "command": "uptime"}); check("ssh read uses ro user + hardened opts", "mcp-ro@192.0.2.1" in t and "StrictHostKeyChecking=yes" in t and "exit_code: 3" in t and "/k/ro" in t, t)
    e, t = call("ssh_exec", {"host": "pve", "command": "touch /x", "mode": "write"}); check("write needs reason/backup", e, t)
    e, t = call("ssh_exec", {"host": "pve", "command": "systemctl restart xray", "mode": "write", "reason": "apply config change", "backup_note": "copied config to tmp"}); check("disruptive blocked", e and "disruptive" in t, t)
    e, t = call("ssh_exec", {"host": "pve", "command": "touch /x", "mode": "write", "reason": "create marker file", "backup_note": "file did not exist before"}); check("write ok uses rw user", not e and "root@192.0.2.1" in t and "/k/rw" in t, t)
    e, t = call("ssh_exec", {"host": "ro", "command": "touch /x", "mode": "write", "reason": "create marker file", "backup_note": "file did not exist before"}); check("write refused on ro-only host", e, t)
    e, t = call("ssh_exec", {"host": "nope", "command": "id"}); check("unknown host refused", e, t)
    e, t = call("ssh_download", {"host": "pve", "remote_path": "/etc/hostname", "tmp_path": "dl/hostname"}); check("download builds scp (fake exits 3 -> error)", e and "scp failed" in t, t)
    e, t = call("ssh_download", {"host": "pve", "remote_path": "-oProxyCommand=x", "tmp_path": "dl/h"}); check("download rejects option-like path", e, t)
    e, t = call("ssh_upload", {"host": "pve", "remote_path": "/tmp/x", "tmp_path": "d/m.txt"}); check("upload needs reason", e, t)
    e, t = call("audit_tail", {"lines": 5}); check("audit_tail", '"ev":"tool"' in t, t)
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
