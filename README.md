# mcpgateway

A self-hosted [MCP](https://modelcontextprotocol.io) gateway for managing a home lab and a few remote servers from an AI assistant. One static Go binary, one SQLite file, no external services.

The gateway gives the assistant five tools, a searchable knowledge base about your infrastructure, and a guarded way to run commands over SSH.

## Features

- **Knowledge base (`kb`, `fs`)** – Markdown cards in SQLite with full-text search (FTS5), version history, trash and verified snapshots. Long notes can be read by section; edits can be applied as small patches instead of rewriting a whole card.
- **SSH (`ssh`)** – runs commands on registered hosts in two modes:
  - `read` – inspection only; uses a read-only key restricted on the host by `mcp-ro-shell`;
  - `write` – requires a reason and a backup note, is checked for disruptive commands and is written to the audit log.

  Supports command batches, background jobs, and gateway-side `grep | head | tail | wc | sort | uniq` filtering to keep output small.
- **Network (`net`)** – network-device commands (for example RouterOS `print`).
- **Status (`status`)** – gateway state and a compact, filterable audit log.
- **OAuth 2.1** (dynamic client registration, PKCE) for MCP clients, a web UI, and Cloudflare Turnstile on remote login.
- **Safe output** – private keys, tokens and passwords are masked in command output and in the audit log; large outputs are trimmed to the start and the end.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Go sources, web UI (`ui.html`, embedded), unit and end-to-end tests |
| `bin/mcpgw-linux-amd64` | Prebuilt Linux binary, checksum in `bin/SHA256SUMS` |
| `deploy/` | systemd units, nftables rules, LXC install script, certificate renewal scripts, `mcp-ro-shell`, `config.example.json` |

## Build

Go 1.24, no CGO. The build is reproducible: the same sources and flags give a bit-identical binary.

```
cd src
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -buildvcs=false -trimpath -ldflags="-s -w" -o ../bin/mcpgw-linux-amd64 .
sha256sum ../bin/mcpgw-linux-amd64
```

Expected SHA-256 for v0.2.1:
`db5aaf9734ecceaecb349c23aac49c09104779b509f8e1e44e5eb3af53dc415f`

## Test

```
cd src
go vet ./... && go test ./...
python3 e2e_test.py ./mcpgw && python3 e2e_remote.py ./mcpgw
python3 e2e_ui.py ./mcpgw      # needs Python Playwright with Chromium
```

## Deploy

1. Copy `deploy/config.example.json` to `/etc/mcpgw/config.json` and adjust hosts and addresses (the values in the example are placeholders).
2. Install the binary, the systemd units and the nftables rules; `deploy/install-lxc.sh` covers an LXC container.
3. On every host that should accept read-only SSH, install `deploy/mcp-ro-shell` and bind the read-only key to it with `command="/usr/local/sbin/mcp-ro-shell",restrict` in `authorized_keys`.

### `mcp-ro-shell`

A small bash forced command, not a service. It allows a fixed list of inspection commands (`ls`, `cat`, `ps`, `systemctl status`, `docker ps`, `zpool status`, ...), optionally piped into simple filters, and refuses everything else, including quoting, redirection and command chaining. It is a second lock on the host, independent of the checks in the gateway.

## Changelog

### v0.2.1
- Read-mode pipelines the gateway cannot run itself (`cut`, `nl`, `column`, unusual options) are passed to the host unchanged; `mcp-ro-shell` decides.

### v0.2.0
- `status op=audit`: compact one-line events, filters `host`, `tool`, `filter_op`, `errors`, `since`, `grep`; `full=true` for raw JSON.
- `fs`: `patch` and `append_section`.
- `ssh`: `commands[]` batches, `background=true` with `op=job`, gateway-side output filters in read mode, `log_node` for knowledge-base log entries.
- Secret masking in output and audit log.
- Fewer false positives in the disruptive-command check (`iptables -S/-L`, `nft list`, `sysctl` reads, RouterOS `print`).
- `kb op=index`: a long document and its outline are listed once.

### Earlier releases (v1 - v4b)
Sources were restored from the original development history; every release rebuilds to a bit-identical binary.
