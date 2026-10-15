# pihole-mcp

An [MCP](https://modelcontextprotocol.io) server for **Pi-hole v6** that lets AI agents analyse your DNS traffic, assess your block lists, and — only when you allow it — change them.

Ask things like:

- *"Which sites got blocked most this week, and by which devices?"*
- *"Is my smart fridge phoning home? What does it talk to?"*
- *"Are any of my block lists dead, stale or redundant?"*
- *"Suggest improvements to my ad blocking."*
- *"Is the network healthy? Is anything bypassing Pi-hole?"*

It talks to Pi-hole only through its **official v6 REST API** (no database access), so it works from anywhere that can reach Pi-hole. One static binary / small container; stdio and Streamable HTTP transports.

> **Status:** early release. Tested against Pi-hole Core 6.4 / FTL 6.7. Requires FTL ≥ 6.0.

## Safety model — please read

- **Read-only by default.** Out of the box the server can only *read* from Pi-hole. The change tools do not even exist until you set `PIHOLE_MCP_ALLOW_WRITES=true`.
- **Two-step changes.** Every change tool first returns a *preview* (the exact API request, current vs. new state, the estimated impact) and a short-lived HMAC `confirm_token`. Nothing changes until the same call is repeated with that token. Changed arguments or an expired token are rejected.
- **An app password has full API rights.** Pi-hole has no API scopes: the app password you give this server could do anything the web UI can. The read-only default, the allowlist (`writes.allowed_tools`) and the confirm flow are *this server's* safety layer — not Pi-hole's. Treat the password and the MCP token as secrets.
- The server **never** touches the web UI password, authentication settings, Teleporter, DHCP or general `/config`.
- Every applied change is written to an audit log (structured, no secrets).

See [docs/security.md](docs/security.md) for the threat model and hardening checklist.

## Quick start

1. In the Pi-hole web UI go to **Settings → Web interface / API → Configure app password** and create an app password.
2. Pick how to run it.

### Claude Code (stdio, via Docker)

```bash
claude mcp add pihole -- docker run -i --rm \
  -e MCP_TRANSPORT=stdio -e PIHOLE_URL=http://pi.hole \
  -e PIHOLE_APP_PASSWORD="<app password>" \
  ghcr.io/salehparsa/pihole-mcp:latest
```

### Claude Code (stdio, local binary)

```bash
claude mcp add pihole --env PIHOLE_URL=http://pi.hole --env PIHOLE_APP_PASSWORD="<app password>" -- /usr/local/bin/pihole-mcp
```

### Claude Desktop

Copy a block from [deploy/claude-desktop.example.json](deploy/claude-desktop.example.json) into your `claude_desktop_config.json`.

### Always-on server on your network (Streamable HTTP)

Run the container next to Pi-hole ([deploy/docker-compose.example.yml](deploy/docker-compose.example.yml)):

```bash
docker run -d --name pihole-mcp -p 8765:8765 \
  -e PIHOLE_URL=http://pi.hole -e PIHOLE_APP_PASSWORD="<app password>" \
  -e MCP_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/salehparsa/pihole-mcp:latest
```

Then, from any machine:

```bash
claude mcp add --transport http pihole http://<host>:8765/mcp --header "Authorization: Bearer $MCP_TOKEN"
```

The HTTP transport **requires** a bearer token (`MCP_TOKEN` / `MCP_TOKEN_FILE`) and refuses to start without one. Publish the port only on a LAN address you trust, or put TLS in front of it (native TLS: `MCP_TLS_CERT_FILE` / `MCP_TLS_KEY_FILE`).

### From source

```bash
go build -o pihole-mcp ./cmd/pihole-mcp
PIHOLE_URL=http://pi.hole PIHOLE_APP_PASSWORD=... ./pihole-mcp config validate
```

## Configuration

Single-instance setups need only `PIHOLE_URL` and `PIHOLE_APP_PASSWORD`. Everything else — multiple Pi-holes, time zone, thresholds, secrets from files, write gating — is documented in [docs/configuration.md](docs/configuration.md); a commented example is in [config.example.yaml](config.example.yaml). Precedence: flags > environment > YAML file > defaults. Secrets can come from files (`*_FILE`) for Docker/Kubernetes secrets.

```bash
pihole-mcp config validate   # fail fast with a clear message
pihole-mcp config print      # effective config, secrets redacted
```

## What it can do

Full reference with every argument: [docs/tools.md](docs/tools.md) (generated from the code).

| Area | Tools |
|---|---|
| Usage | `get_summary`, `top_domains`, `top_clients`, `blocked_by_device`, `client_activity`, `query_timeline`, `search_queries`, `explain_domain`, `list_devices`, `list_instances` |
| Block lists & rules | `list_blocklists`, `list_domain_rules`, `assess_blocklists` |
| Health & advice | `network_health`, `get_pihole_messages`, `suggest_improvements` |
| Changes *(opt-in, two-step)* | `add_blocklist`, `remove_blocklist`, `set_blocklist_enabled`, `add_domain_rule`, `remove_domain_rule`, `update_gravity`, `set_blocking` |

It also offers four prompts (`weekly_report`, `assess_blocklists`, `investigate_device`, `improve_adblocking`) and resources (`pihole://catalog/blocklists`, `pihole://{instance}/status`).

Aggregations scan the query log up to `analysis.max_scan` entries and say so (`scanned`, `truncated`, and the time range actually covered) so an agent knows when numbers are partial. The server supplies *evidence*; the agent writes the advice.

## Development

```bash
make check        # gofmt, vet, tests (race), docs up to date
make lint vuln    # golangci-lint, govulncheck
make docker       # build the image locally
make inspector    # MCP Inspector against the stdio binary
```

Tests run against an in-memory fake Pi-hole built from sanitized fixtures in `testdata/` — they never need (or touch) a real Pi-hole. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

pihole-mcp is an **independent, unofficial** project. It is not affiliated with, endorsed by, or sponsored by the Pi-hole project; "Pi-hole" is a trademark of Pi-hole LLC, used here only to describe compatibility.

This software is provided **"as is", without warranty of any kind**, and the authors are not liable for any damages or losses arising from its use — including misconfigured DNS blocking, network outages, exposure of DNS data, or the actions of any AI agent connected to it. You are responsible for how you configure and expose it, and for reviewing every change before confirming it. See the Apache-2.0 license (sections 7 and 8) for the full terms.

Block lists in the built-in catalog are only linked, never bundled; each is governed by its own license and terms.

## License

[Apache-2.0](LICENSE). Bundled third-party software and its licenses: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md); see also [NOTICE](NOTICE).
