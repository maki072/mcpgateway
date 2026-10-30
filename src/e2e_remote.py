#!/usr/bin/env python3
"""End-to-end test of the remote-login policy (Turnstile + mandatory TOTP + per-IP lockout).
Usage: e2e_remote.py ./mcpgw
A fake siteverify server stands in for Cloudflare; loopback addresses 127.0.0.x act as different clients."""
import base64, hashlib, hmac, http.client, http.server, json, os, secrets, ssl, struct, subprocess, sys, tempfile, threading, time, urllib.parse

BIN = os.path.abspath(sys.argv[1])
T = tempfile.mkdtemp(prefix="mcpgw-rem-")
PORT, VPORT = 18445, 18446
BASE = f"https://127.0.0.1:{PORT}"
SITEKEY = "1x00000000000000000000AA"  # public Cloudflare test key; also used as a plain string here
SECRET = "test-secret-not-real"
PASS = "correct horse battery staple"

def sh(*a): subprocess.run(a, check=True, capture_output=True)
sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{T}/k.pem", "-out", f"{T}/c.pem",
   "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1")
ctx = ssl.create_default_context(cafile=f"{T}/c.pem")
open(f"{T}/ts.secret", "w").write(SECRET + "\n")

salt = os.urandom(16)
HASH = hashlib.pbkdf2_hmac("sha256", PASS.encode(), salt, 600000, 32).hex()
sec = os.urandom(20); B32 = base64.b32encode(sec).decode().rstrip("=")

def totp(step):
    d = hmac.new(sec, struct.pack(">Q", step), hashlib.sha1).digest()
    o = d[-1] & 15
    return "%06d" % ((struct.unpack(">I", d[o:o+4])[0] & 0x7fffffff) % 1000000)

_idx = [0]
def reset_totp(): _idx[0] = 0
def fresh_totp():
    """The server accepts steps now-1..now+1 and rejects a step it has already seen, so one server instance
    can verify at most three distinct valid codes. The offset is applied to the clock at call time, so a
    30 s boundary between calls cannot push a code out of the window."""
    assert _idx[0] < 3, "test used more than three valid TOTP codes on one server"
    st = int(time.time()) // 30 + _idx[0] - 1
    _idx[0] += 1
    return totp(st)

# ---- fake siteverify ----
seen, calls = set(), []
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        f = urllib.parse.parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        tok = f.get("response", [""])[0]
        calls.append({"secret": f.get("secret", [""])[0], "remoteip": f.get("remoteip", [""])[0], "tok": tok})
        if tok.startswith("http500"):
            self.send_response(500); self.end_headers(); return
        r = {"success": True, "action": "login", "hostname": "mcp.example", "error-codes": []}
        if f.get("secret", [""])[0] != SECRET: r = {"success": False, "error-codes": ["invalid-input-secret"]}
        elif tok.startswith("bad"): r = {"success": False, "error-codes": ["invalid-input-response"]}
        elif tok.startswith("wrongaction"): r["action"] = "other"
        elif tok.startswith("wronghost"): r["hostname"] = "evil.example"
        elif tok.startswith("good"):
            if tok in seen: r = {"success": False, "error-codes": ["timeout-or-duplicate"]}
            seen.add(tok)
        else: r = {"success": False, "error-codes": ["invalid-input-response"]}
        b = json.dumps(r).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", VPORT), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

def tsn(): return "good-" + secrets.token_hex(6)

fails = 0
def check(name, cond, extra=""):
    global fails
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(extra)) if (not cond and extra) else ""))
    if not cond: fails += 1

def start(tag, trusted, totp_on=True, ts_on=True, skip=None, extra=None):
    reset_totp()
    d = f"{T}/{tag}"; os.makedirs(d)
    a = {"salt": salt.hex(), "hash": HASH, "iter": 600000}
    if totp_on: a["totp_secret"] = B32
    json.dump(a, open(f"{d}/auth.json", "w")); os.chmod(f"{d}/auth.json", 0o600)
    cfg = {"listen": f"127.0.0.1:{PORT}", "public_url": BASE, "cert_file": f"{T}/c.pem", "key_file": f"{T}/k.pem",
           "kb_dir": f"{d}/kb", "kb_db": f"{d}/kb.db", "backup_dir": f"{d}/backup", "tmp_dir": f"{d}/tmp", "state_file": f"{d}/state.json",
           "auth_file": f"{d}/auth.json", "audit_log": f"{d}/audit.log", "known_hosts": f"{d}/kh",
           "api_cidrs": ["127.0.0.0/8"], "login_cidrs": ["0.0.0.0/0", "::/0"], "trusted_cidrs": trusted,
           "redirect_allow": ["https://claude.ai/api/mcp/auth_callback"], "hosts": {}}
    if skip is not None: cfg["trusted_skip_totp"] = skip
    if extra: cfg.update(extra)
    if ts_on:
        cfg.update({"turnstile_sitekey": SITEKEY, "turnstile_secret_file": f"{T}/ts.secret", "turnstile_hostnames": ["mcp.example"],
                    "turnstile_verify_url": f"http://127.0.0.1:{VPORT}/siteverify"})
    json.dump(cfg, open(f"{d}/config.json", "w"))
    p = subprocess.Popen([BIN, "-config", f"{d}/config.json"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(60):
        try: req("GET", "/healthz"); break
        except Exception: time.sleep(0.2)
    return p, d

def stop(p):
    p.terminate(); p.wait(timeout=10)

def req(method, path, body=None, headers=None, form=None, src="127.0.0.1"):
    u = urllib.parse.urlparse(BASE + path)
    c = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=30, source_address=(src, 0))
    hd = dict(headers or {}); data = None
    if form is not None: data = urllib.parse.urlencode(form); hd["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None: data = json.dumps(body); hd["Content-Type"] = "application/json"
    c.request(method, u.path + ("?" + u.query if u.query else ""), data, hd)
    r = c.getresponse(); b = r.read().decode()
    return r.status, dict(r.getheaders()), b

BADCODE = "000000"
def login(src, ts, pw=PASS, code=BADCODE):
    return req("POST", "/ui/api/login", {"pass": pw, "totp": code, "ts": ts}, src=src)

def audit(d): return open(f"{d}/audit.log").read()

REMOTE = ["10.0.0.0/8"]  # loopback is NOT trusted -> every test client is a remote one
procs = []
try:
    # ---------- group 1: remote policy ----------
    p, d = start("g1", REMOTE); procs.append(p)
    s, _, b = req("GET", "/ui/api/session"); j = json.loads(b)
    check("session info: remote, sitekey, totp required", j.get("remote") and j.get("sitekey") == SITEKEY and j.get("need_totp") and j.get("remote_ready"), j)
    s, hd, page = req("GET", "/ui/")
    check("UI CSP allows Cloudflare only for remote", "challenges.cloudflare.com" in hd.get("Content-Security-Policy", "") and "frame-src https://challenges.cloudflare.com" in hd["Content-Security-Policy"], hd.get("Content-Security-Policy"))
    check("UI CSP has no unsafe-inline script", "script-src 'nonce-" in hd["Content-Security-Policy"] and "unsafe" not in hd["Content-Security-Policy"].split("script-src")[1].split(";")[0])

    s, _, b = req("POST", "/ui/api/login", {"pass": PASS, "totp": BADCODE}); check("missing CAPTCHA token -> 400", s == 400, (s, b))
    s, _, b = login("127.0.0.1", "wrongaction-1"); check("action mismatch -> 400", s == 400, (s, b))
    s, _, b = login("127.0.0.1", "wronghost-1"); check("hostname mismatch -> 400", s == 400, (s, b))
    s, _, b = login("127.0.0.1", "bad-1"); check("rejected token -> 400", s == 400, (s, b))
    check("error text hides verifier details", "invalid-input" not in b and "mcp.example" not in b, b)
    t1 = tsn()
    s, hd, b = login("127.0.0.1", t1, code=fresh_totp())
    check("valid CAPTCHA + passphrase + TOTP -> 200 and session cookie", s == 200 and "mcpgw_ui" in hd.get("Set-Cookie", "") and "Secure" in hd["Set-Cookie"] and "HttpOnly" in hd["Set-Cookie"], (s, hd.get("Set-Cookie")))
    cookie = hd["Set-Cookie"].split(";")[0]; csrf = json.loads(b)["csrf"]
    check("siteverify got secret and client address", any(c["tok"] == t1 and c["secret"] == SECRET and c["remoteip"] == "127.0.0.1" for c in calls), calls[-1:])
    s, _, _ = req("GET", "/ui/api/list?root=kb&path=.", headers={"Cookie": cookie}); check("session works from the same address", s == 200, s)
    s, _, _ = req("GET", "/ui/api/list?root=kb&path=.", headers={"Cookie": cookie}, src="127.0.0.2"); check("session rejected from another address", s == 401, s)
    s, _, _ = req("GET", "/ui/api/list?root=kb&path=.", headers={"Cookie": cookie}); check("session was dropped after address mismatch", s == 401, s)
    log = audit(d)
    check("scheduled backup of an empty database succeeds", '"ev":"backup"' in log and '"ok":true' in log, log[:400])
    check("audit has captcha failures with reasons, no secrets", "login_captcha_fail" in log and "action mismatch" in log and SECRET not in log and PASS not in log)
    stop(p); procs.remove(p)

    # ---------- group 2: replay, unreachable verifier, per-IP lockout ----------
    p, d = start("g2", REMOTE); procs.append(p)
    s, _, b = login("127.0.0.1", "http500-1"); check("verifier error fails closed", s == 400, (s, b))
    t = tsn(); codeA = fresh_totp()
    s, _, _ = login("127.0.0.1", t, code=codeA); check("login ok", s == 200)
    s, _, _ = login("127.0.0.1", t, code=fresh_totp()); check("CAPTCHA token cannot be reused", s == 400, s)
    s, _, _ = login("127.0.0.1", tsn(), code=codeA); check("TOTP code cannot be reused", s == 401, s)
    s, _, b = login("127.0.0.1", tsn(), code=BADCODE); check("wrong TOTP -> 401", s == 401, (s, b))
    s, _, b = login("127.0.0.1", tsn(), pw="wrong passphrase!!"); check("wrong passphrase -> 401", s == 401, (s, b))
    # 127.0.0.5 gets locked after five failures, and the lock must not affect other addresses
    for i in range(5): s, _, _ = login("127.0.0.5", tsn(), pw="nope-%d" % i)
    s, _, b = login("127.0.0.5", tsn()); check("client locked after five failures (even with correct credentials)", s == 429, (s, b))
    s, _, b = login("127.0.0.6", tsn(), code=fresh_totp()); check("other address is not affected by the lock", s == 200, (s, b))
    log = audit(d)
    check("audit records lockout", '"lockout":true' in log and "login_locked" in log)
    stop(p); procs.remove(p)

    # ---------- group 3: remote login is refused unless both TOTP and CAPTCHA are configured ----------
    for tag, kw in (("g3a", {"totp_on": False}), ("g3b", {"ts_on": False})):
        p, d = start(tag, REMOTE, **kw); procs.append(p)
        s, _, b = login("127.0.0.1", tsn(), code=BADCODE); check(tag + ": remote UI login refused (403)", s == 403, (s, b))
        s, _, b = req("GET", "/ui/api/session"); j = json.loads(b); check(tag + ": session info says not ready", j.get("remote") and not j.get("remote_ready"), j)
        # the OAuth page must also refuse
        s, _, b = req("POST", "/register", {"client_name": "c", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]}); cid = json.loads(b)["client_id"]
        qs = urllib.parse.urlencode({"response_type": "code", "client_id": cid, "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "state": "s", "code_challenge": "A" * 43, "code_challenge_method": "S256"})
        s, _, b = req("GET", "/authorize?" + qs); check(tag + ": remote /authorize refused (403)", s == 403, (s, b))
        stop(p); procs.remove(p)

    # ---------- group 4: /authorize form for a remote client ----------
    p, d = start("g4", REMOTE); procs.append(p)
    s, _, b = req("POST", "/register", {"client_name": "Claude", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]}); cid = json.loads(b)["client_id"]
    redir = "https://claude.ai/api/mcp/auth_callback"
    qs = urllib.parse.urlencode({"response_type": "code", "client_id": cid, "redirect_uri": redir, "state": "xyz", "code_challenge": "A" * 43, "code_challenge_method": "S256"})
    s, hd, page = req("GET", "/authorize?" + qs)
    csp = hd.get("Content-Security-Policy", "")
    check("authorize page shows widget with action and sitekey", s == 200 and 'class="cf-turnstile"' in page and f'data-sitekey="{SITEKEY}"' in page and 'data-action="login"' in page, page[-400:])
    check("authorize page loads the Cloudflare script", "https://challenges.cloudflare.com/turnstile/v0/api.js" in page)
    check("authorize CSP allows Cloudflare, no form-action restriction", "script-src https://challenges.cloudflare.com" in csp and "frame-src https://challenges.cloudflare.com" in csp and "form-action" not in csp, csp)
    check("authorize page asks for the TOTP code", 'name="totp"' in page)
    rid = page.split('name="rid" value="')[1].split('"')[0]
    s, _, _ = req("POST", "/authorize", form={"rid": rid, "pass": PASS, "totp": BADCODE}); check("form without CAPTCHA -> 400", s == 400, s)
    s, hd, fb = req("POST", "/authorize", form={"rid": rid, "pass": PASS, "totp": fresh_totp(), "cf-turnstile-response": tsn()})
    check("form with CAPTCHA + TOTP -> 302 to client with code", s == 302 and hd.get("Location", "").startswith(redir) and "code=" in hd["Location"] and "state=xyz" in hd["Location"], (s, hd.get("Location"), fb[-300:]))
    # /mcp stays closed for unauthenticated callers regardless of login policy
    s, _, _ = req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"}); check("/mcp without token -> 401", s == 401, s)
    stop(p); procs.remove(p)

    # ---------- group 5: trusted network keeps the simple login ----------
    p, d = start("g5", ["127.0.0.0/8"]); procs.append(p)
    s, _, b = req("GET", "/ui/api/session"); j = json.loads(b)
    check("trusted: no TOTP, no CAPTCHA required", not j.get("remote") and not j.get("need_totp") and "sitekey" not in j, j)
    s, hd, _ = req("GET", "/ui/")
    check("trusted: UI CSP does not open Cloudflare", "challenges.cloudflare.com" not in hd.get("Content-Security-Policy", ""))
    s, _, b = req("POST", "/ui/api/login", {"pass": PASS}); check("trusted: passphrase alone logs in", s == 200, (s, b))
    stop(p); procs.remove(p)
    p, d = start("g5b", ["127.0.0.0/8"], skip=False); procs.append(p)
    s, _, b = req("POST", "/ui/api/login", {"pass": PASS}); check("trusted_skip_totp=false: passphrase alone refused", s == 401, (s, b))
    s, _, b = req("POST", "/ui/api/login", {"pass": PASS, "totp": fresh_totp()}); check("trusted_skip_totp=false: passphrase + TOTP ok", s == 200, (s, b))
    stop(p); procs.remove(p)

    # ---------- group 5c: remote_require_totp=false -> passphrase + CAPTCHA only ----------
    p, d = start("g5c", REMOTE, totp_on=False, extra={"remote_require_totp": False}); procs.append(p)
    s, _, b = req("GET", "/ui/api/session"); j = json.loads(b)
    check("no-TOTP mode: remote ready, no code asked", j.get("remote_ready") and not j.get("need_totp") and j.get("sitekey"), j)
    s, _, b = req("POST", "/ui/api/login", {"pass": PASS}); check("no-TOTP mode: passphrase without CAPTCHA -> 400", s == 400, (s, b))
    s, _, b = login("127.0.0.1", "bad-1"); check("no-TOTP mode: bad CAPTCHA -> 400", s == 400, (s, b))
    s, _, b = login("127.0.0.1", tsn(), pw="wrong passphrase!!"); check("no-TOTP mode: wrong passphrase -> 401", s == 401, (s, b))
    s, _, b = login("127.0.0.1", tsn()); check("no-TOTP mode: passphrase + CAPTCHA -> 200", s == 200, (s, b))
    for i in range(5): login("127.0.0.7", tsn(), pw="nope-%d" % i)
    s, _, b = login("127.0.0.7", tsn()); check("no-TOTP mode: per-address lockout still applies", s == 429, (s, b))
    stop(p); procs.remove(p)

    # ---------- group 6: connection limits and startup validation ----------
    p, d = start("g6", REMOTE); procs.append(p)
    socks = []
    import socket
    for i in range(25):
        try:
            sck = socket.create_connection(("127.0.0.1", PORT), timeout=3); socks.append(sck)
        except Exception: break
    time.sleep(0.3)
    alive = 0
    for sck in socks:
        sck.settimeout(0.3)
        try:
            if sck.recv(1) == b"": pass
            else: alive += 1
        except socket.timeout: alive += 1
        except Exception: pass
    check("per-address connection cap (20) drops the surplus", 15 <= alive <= 21, alive)
    for sck in socks: sck.close()
    stop(p); procs.remove(p)

    d = f"{T}/g7"; os.makedirs(d)
    shutil_cfg = json.load(open(f"{T}/g6/config.json")); shutil_cfg["turnstile_secret_file"] = f"{T}/missing.secret"
    json.dump(shutil_cfg, open(f"{d}/config.json", "w"))
    r = subprocess.run([BIN, "-config", f"{d}/config.json"], capture_output=True, text=True, timeout=20)
    check("missing Turnstile secret file -> refuses to start", r.returncode != 0 and "turnstile" in (r.stdout + r.stderr).lower(), (r.returncode, (r.stdout + r.stderr)[-200:]))
finally:
    for p in procs:
        try: stop(p)
        except Exception: pass
    srv.shutdown()
print("\nFAILS:", fails)
sys.exit(1 if fails else 0)
