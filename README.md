# mcpgateway

Self-hosted MCP gateway (Go, one static binary). Tools: `kb`, `fs`, `ssh`, `net`, `status`. OAuth 2.1 (DCR + PKCE), SQLite knowledge base (FTS5, version history, trash, verified snapshots), web UI, Cloudflare Turnstile for remote login, per-host read-only and read-write SSH keys, audit log.

## Layout

| Path | What it is |
|---|---|
| `src/` | Go sources of version v4b, `go.mod`/`go.sum`, the web UI (`ui.html`, embedded) and the end-to-end tests (`e2e_test.py`, `e2e_ui.py`, `e2e_remote.py`). |
| `bin/mcpgw-linux-amd64` | Binary v4b as deployed in CT 105, checksum in `bin/SHA256SUMS`. |
| `deploy/` | systemd units, nftables rules, LXC install script, certificate renewal, `mcp-ro-shell` (forced command for read-only SSH keys), `config.example.json`. Hostnames and LAN addresses are examples. |

## Where the sources come from

The sources were rebuilt on 2026-10-30 by replaying every file write and edit of the original build session (claude.ai chat "MCP-сервер для домашней сети", 2026-10-24..26) on top of the first released bundle. The Go build is reproducible, so every intermediate release was checked against the binary that had been deployed:

| Release | sha256 (first 16) | Rebuilt binary |
|---|---|---|
| v1 | 69b89c14e0c057a6 | identical |
| v1b (`mcpgw.xz`) | fe1702dfa40ba05c | identical |
| v2 | 2ef2dd0c10c057d5 | identical |
| v2b | f29a3dbc5fd51004 | identical |
| v3 | 7fdc3c55ba5b1367 | identical |
| v3b | d9ae927fbdfa68dc | identical |
| v3c | 1877e14a4936b211 | identical |
| v4 | e8e0dd4ee9fc5bee | identical |
| v4b | 09b58af5e203eeaa | identical |

## Build (reproduces the v4b binary bit for bit)

Go 1.24.7, outside a git checkout or with `-buildvcs=false` (VCS stamping changes the binary):

```
cd src
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o ../bin/mcpgw-linux-amd64 .
sha256sum ../bin/mcpgw-linux-amd64   # 09b58af5e203eeaae919e83489ac8706212ede2805f9475a18f6eb591bd9225a
```

## Tests

```
cd src
go vet ./... && go test ./...
python3 e2e_test.py ./mcpgw && python3 e2e_ui.py ./mcpgw && python3 e2e_remote.py ./mcpgw
```

`e2e_ui.py` needs Python Playwright with Chromium. All suites pass on v4b (2026-10-30).

## Secrets

Nothing secret belongs in this repository: no SSH keys, passwords, tokens, certificates, `auth.json`, real `config.json`, `known_hosts`, Turnstile or Cloudflare secrets, databases (see `.gitignore`). On the gateway they live in `/etc/mcpgw/` and `/var/lib/mcpgw/`.
