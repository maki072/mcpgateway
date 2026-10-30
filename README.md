# mcpgateway

Self-hosted MCP gateway (Go, one static binary). Tools: `kb`, `fs`, `ssh`, `net`, `status`. OAuth 2.1 (DCR + PKCE), SQLite knowledge base, audit log, read-only and read-write SSH keys per host.

## Repository status (read this first)

The Go sources of the current binary (v2 to v4b: SQLite knowledge base, web UI, backups, Turnstile login, combined tools) were **not found** on the owner's PC or in the container. This repository therefore contains:

| Path | What it is |
|---|---|
| `bin/mcpgw-linux-amd64` | Current binary (v4b, linux/amd64, Go 1.24.7, `CGO_ENABLED=0`, `-trimpath`). Checksum in `bin/SHA256SUMS`. |
| `src-v1-legacy/` | Source of the first version (2026-10-24, before SQLite). It does **not** match the binary above. |
| `deploy/` | systemd units, nftables rules, LXC install script, certificate renewal, `mcp-ro-shell` (forced command for read-only SSH keys), `config.example.json` (v1 fields). |

Build info of the binary: module `mcpgw`, dependencies `modernc.org/sqlite v1.38.2`, `github.com/google/uuid v1.6.0`, `github.com/dustin/go-humanize v1.0.1`, `golang.org/x/sys v0.34.0` and others.

When the current sources are found, put them in `src/` and remove `src-v1-legacy/`.

## Build

```
cd src
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o ../bin/mcpgw-linux-amd64 .
sha256sum ../bin/mcpgw-linux-amd64 > ../bin/SHA256SUMS
```

## Secrets

Nothing secret belongs in this repository: no SSH keys, passwords, tokens, certificates, `auth.json`, real `config.json`, `known_hosts` or databases (see `.gitignore`). On the gateway they live in `/etc/mcpgw/` and `/var/lib/mcpgw/`.