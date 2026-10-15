# pihole-mcp: an open-source Go MCP server for Pi-hole v6

## Context
The maintainer wants an **MCP server in Go** so agents can:
1. analyse DNS usage;
2. update block lists;
3. suggest improvements to the network and ad blocking;
4. assess block lists and network health;
5. answer questions like "which sites get blocked most, and by which devices?".

It will be **open-sourced**: it must be reusable by anyone, configurable, and published as a Docker image to **GHCR via GitHub Actions**.  **This plan is written so any subagent can implement one milestone on its own.** Step 0 copies it into the repo as `docs/PLAN.md`.

**The maintainer's own deployment is the first user, not a built-in assumption.** Nothing specific to any one setup (IPs, host names, time zone, upstreams) may be hardcoded in this repo; it lives only in the deployer's compose file and `.env`.

### Decisions (confirmed with the maintainer)
- **Transport:** one binary with two modes. `stdio` for local use (Claude Code or Claude Desktop starting the binary or container). **Streamable HTTP** (`/mcp`, bearer token) for agents on the network. The main deployment is a container next to Pi-hole.
- **Changes to Pi-hole:** off by default (`writes.enabled=false`). Every change tool works in two calls: preview first, then confirm with a token.
- **Data source:** the Pi-hole v6 REST API only, with an **app password**. No direct SQLite access, so the server works from anywhere.
- **Hard rules (also go in `CLAUDE.md`):**
  - Never touch the web UI password or auth config, teleporter, DHCP, or general `/config` writes.
  - No git commits or pushes unless the maintainer asks; `git init` is fine.
  - No personal data in the repo: test fixtures must be sanitized (fake device names, `192.0.2.x`/`2001:db8::` IPs, fake MACs) and contain no secrets.

### Open questions to settle in M0 (ask the maintainer; don't block other work)
- **Module path / GitHub owner:** `github.com/<owner>/pihole-mcp`. Use the placeholder `github.com/salehparsa/pihole-mcp` until confirmed. The image is `ghcr.io/<owner>/pihole-mcp`.
- **License:** recommend **Apache-2.0** (explicit patent grant). MIT is the alternative.

## Tech stack
- **Go 1.26.** The Mac has go1.26.2 darwin/amd64.
- **MCP SDK:** `github.com/modelcontextprotocol/go-sdk` **v1.8.0**, the official SDK and latest stable as of 2026-09.
  - `mcp.NewServer(&mcp.Implementation{Name:"pihole-mcp",Version:version}, opts)`.
  - Typed tools: `mcp.AddTool(srv, &mcp.Tool{…, Annotations}, func(ctx, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error))`. Schemas are inferred from the structs; use `jsonschema:"…"` tags for descriptions.
  - stdio: `srv.Run(ctx, &mcp.StdioTransport{})`.
  - HTTP: `mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)`.
  - Prompts: `srv.AddPrompt`. Resources: `srv.AddResource`.
  - Tests: `mcp.NewInMemoryTransports()`.
- **Dependencies:** the standard library plus a YAML library (`go.yaml.in/yaml/v3`) for the config file. Keep the dependency list minimal and justify any addition in the PR description.
- **Version info:** `-ldflags "-X main.version=… -X main.commit=… -X main.date=…"`, shown by `pihole-mcp --version` and sent as the MCP server version.

## Configuration (`internal/config`) — everything configurable, safe defaults
**Precedence:** flags > environment variables > YAML file (`--config` / `PIHOLE_MCP_CONFIG`) > defaults. **Every secret** can also be read from a file through a `*_FILE` env var (works with Docker/Kubernetes secrets). `pihole-mcp config validate` and `pihole-mcp config print` (secrets redacted) help with setup.

```yaml
# config.example.yaml (shipped in repo root; documented field-by-field in docs/configuration.md)
instances:                      # one or more Pi-holes; first is default
  - name: home                  # used as the `instance` tool argument
    url: http://pi.hole         # env (single-instance shortcut): PIHOLE_URL
    password_file: /run/secrets/pihole_app_password   # or password: / PIHOLE_APP_PASSWORD(_FILE)
    tls_skip_verify: false      # for self-signed Pi-hole HTTPS
    timeout: 10s
server:
  transport: stdio              # stdio | http        (MCP_TRANSPORT)
  listen: ":8765"               #                     (MCP_LISTEN)
  path: /mcp
  auth_token_file: ""           # required for http   (MCP_TOKEN / MCP_TOKEN_FILE)
  tls_cert_file: ""             # optional native TLS
  tls_key_file: ""
  allowed_origins: []           # Origin check for browser clients (DNS-rebinding protection)
writes:
  enabled: false                # PIHOLE_MCP_ALLOW_WRITES
  confirm_secret_file: ""       # HMAC secret; random per process if unset (tokens then don't survive restart)
  confirm_ttl: 5m
  allowed_tools: []             # optional allowlist, e.g. [add_domain_rule, update_gravity]
analysis:
  timezone: UTC                 # IANA TZ for periods/report bucketing (TZ also honoured)
  default_period: 24h
  max_scan: 50000               # cap for /queries paging
  stale_list_days: 7
  high_block_ratio: 0.5         # device flagged above this
  ad_patterns_file: ""          # extra/override heuristic patterns
  catalog_file: ""              # override embedded block-list catalog
log:
  level: info                   # debug|info|warn|error
  format: text                  # text|json
```

Single-instance users only need `PIHOLE_URL` and `PIHOLE_APP_PASSWORD`. **Validation fails fast and clearly**:
- http mode without a token;
- a URL that doesn't parse;
- a password and a password file both set;
- a confirm TTL ≤ 0.

## Pi-hole v6 API facts (from the spec served at `<pihole>/api/docs/specs/*.yaml`)
- **Auth:**
  - `POST /api/auth {"password": "<app password>"}` returns `session.sid` and `session.validity`.
  - Send `X-FTL-SID: <sid>` on every call; on 401, log in again once and retry.
  - `DELETE /api/auth` on shutdown, because sessions are limited (`webserver.api.max_sessions`).
  - App passwords are created in the web UI (Settings → Web interface/API → Expert). **An app password has full API rights; Pi-hole has no scopes, so this server's gating is the safety layer.** The README must say this clearly.
- **Usage:**
  - `/stats/summary` covers the last 24h in memory. `/stats/database/summary?from=&until=` (Unix seconds) covers longer ranges.
  - `/stats/(database/)top_domains` takes `count` and `blocked`. `/stats/(database/)top_clients` takes `blocked`.
  - Also: `/stats/upstreams`, `/stats/query_types`, `/stats/recent_blocked`.
  - `/history`, `/history/clients`, `/history/database[/clients]` give timelines.
- **Query log, `/queries`:**
  - Filters: `from, until, length, start, cursor, domain, client_ip, client_name, upstream, type, status, reply, dnssec, disk`. `disk=true` reads the on-disk DB beyond the 24h in memory.
  - The response `cursor` points to the next page.
  - **Blocked statuses:** GRAVITY, REGEX, DENYLIST, EXTERNAL_BLOCKED_*, *_CNAME variants, SPECIAL_DOMAIN. Confirm the exact enum against `queries.yaml` in M1 and keep it in `pihole.BlockedStatuses`.
- **Block lists:** `/lists`, `/lists/{list}`, `/lists:batchDelete`.
  - Fields: `address, type, comment, groups, enabled, id, date_added, date_modified, date_updated, number, invalid_domains, abp_entries, status`.
- **Domain rules:** `/domains/{allow|deny}/{exact|regex}[/{domain}]`.
- **Lookup:** `/search/{domain}` shows which lists and rules match a domain.
- **Devices and groups:** `/clients`, `/network/devices`, `/groups`.
- **Health:** `/info/{system,sensors,ftl,host,database,version,messages,metrics}`.
- **Actions:**
  - `POST /action/gravity` streams `text/plain` chunked output and can take minutes.
  - `/dns/blocking` (GET/POST) turns blocking on or off.
- **Compatibility:**
  - Check `/info/version` at startup. Warn when FTL is below v6.0, and document the minimum supported version.
  - Code against the published spec, not against one installation.

## Repository layout 
```
cmd/pihole-mcp/main.go          # subcommands: serve (default), config validate|print, version
internal/config/                # load/merge/validate (+ tests for precedence and *_FILE)
internal/pihole/                # typed API client, no MCP knowledge
  client.go auth.go errors.go types.go stats.go queries.go lists.go domains.go
  clients.go info.go network.go actions.go search.go
internal/instances/registry.go  # name → *pihole.Client; default instance; Close all
internal/analysis/              # pure functions, heavily unit-tested
  period.go aggregate.go blocklists.go health.go suggest.go adpatterns.go finding.go
internal/confirm/token.go       # HMAC preview/confirm tokens
internal/tools/                 # MCP registration; thin wrappers over pihole + analysis
  register.go usage.go blocklists.go health.go suggest.go write.go prompts.go resources.go
internal/catalog/blocklists.json  # embedded curated list catalog (HaGeZi, OISD, StevenBlack, …) with notes
testdata/                       # SANITIZED fixtures (see hard rules) + scripts/record-fixtures.sh that sanitizes
deploy/
  docker-compose.example.yml    # generic: pihole + pihole-mcp on one network, secrets via files
  claude-desktop.example.json   # stdio via `docker run -i` and via binary
.github/
  workflows/ci.yml release.yml
  dependabot.yml  ISSUE_TEMPLATE/{bug,feature}.yml  pull_request_template.md
Dockerfile  .dockerignore  .goreleaser.yaml  .golangci.yml  Makefile
config.example.yaml  README.md  LICENSE  CONTRIBUTING.md  SECURITY.md  CODE_OF_CONDUCT.md  CHANGELOG.md
CLAUDE.md                       # hard rules, layout, commands, link to docs/PLAN.md
docs/PLAN.md  docs/configuration.md  docs/tools.md  docs/api-notes.md  docs/security.md
```

## MCP surface
- All tools return typed structured output plus a short text summary.
- Annotations: `ReadOnlyHint` on reads; `DestructiveHint` and `IdempotentHint` on writes.
- **Every tool takes an optional `instance`** (defaults to the first configured instance).
- Time inputs: `period` ("1h", "24h", "7d", "30d") or `from`/`until` (RFC3339). Times are interpreted in `analysis.timezone`.
- `docs/tools.md` is **generated** from the registered tool schemas (`go run ./cmd/pihole-mcp docs > docs/tools.md`), and CI checks that it's up to date.

### Usage analysis (read)
| Tool | What it returns | API |
|---|---|---|
| `get_summary` | totals, % blocked, cached, forwarded, unique domains/clients, gravity size | stats/(database/)summary |
| `top_domains` | top N domains; `blocked` filter; optional `client` (then aggregated from /queries) | stats/(database/)top_domains, queries |
| `top_clients` | top N devices by total or blocked, with names | stats/(database/)top_clients + clients |
| `blocked_by_device` | blocked domain × device matrix; optional `domain`/`client` filter | /queries paged |
| `client_activity` | one device: totals, % blocked, top allowed/blocked domains, query types, active hours | /queries + history/clients |
| `query_timeline` | counts over time (total/blocked, optional per client) | history(/database)(/clients) |
| `search_queries` | raw query log with filters + `cursor` (limit ≤ 500) | /queries |
| `explain_domain` | why a domain is or isn't blocked + recent queries and devices | /search/{domain} + /queries |
| `list_devices` | IP, MAC, name, vendor, last seen, query count | /network/devices, /clients |
| `list_instances` | configured instances with their version and blocking state (no secrets) | /info/version, /dns/blocking |

Aggregations stop at `analysis.max_scan` and report `scanned`, `truncated`, and the actual time range covered, so agents know when numbers are partial.

### Block lists and network health (read)
- `list_blocklists`: all lists with their stats.
- `list_domain_rules`: allow/deny rules, exact and regex.
- `assess_blocklists` returns `[]Finding{Severity, Area, Title, Detail, Evidence, Suggestion}`. It flags:
  - lists whose last update failed;
  - lists not updated for more than `stale_list_days`;
  - disabled lists;
  - lists with zero domains;
  - a high ratio of invalid domains;
  - overlap estimated from a sample;
  - **list contribution**: a sample of the top blocked domains attributed to lists via `/search`, which shows "dead weight" lists;
  - allow regex rules that are too broad.
- `network_health` returns `[]Finding` plus metrics. It covers:
  - load, memory, disk, temperature;
  - FTL messages;
  - upstream response and error counts, and upstream diversity;
  - cache hit ratio, NXDOMAIN and SERVFAIL rates;
  - DNSSEC bogus counts;
  - available updates;
  - database size;
  - **devices that may be bypassing Pi-hole**: known in `/network/devices` but with no recent queries.
- `get_pihole_messages`: FTL diagnostics, passed through.

### Suggestions (read)
`suggest_improvements(period)` returns ranked findings:
- frequently allowed domains that match the ad/tracker heuristics (`adpatterns`, which users can extend);
- devices above `high_block_ratio`;
- block-list problems;
- catalog lists that aren't installed, matched to the current coverage;
- health and upstream issues.

The server supplies the evidence; the agent writes the advice.

### Prompts and resources
- **Prompts:** `weekly_report`, `assess_blocklists`, `investigate_device(client)`, `improve_adblocking`. Each lists which tools to call, and to preview before any change.
- **Resources:** `pihole://catalog/blocklists` (the embedded catalog, or the override file); `pihole://{instance}/status`.

### Change tools (registered only when `writes.enabled`, filtered by `writes.allowed_tools`)
`add_blocklist`, `remove_blocklist`, `set_blocklist_enabled`, `add_domain_rule`, `remove_domain_rule`, `update_gravity`, `set_blocking(enabled, timer_seconds)`.

**Preview, then confirm:**
1. A call without `confirm_token` changes nothing. It returns a preview (the exact request, current vs. new state, and its impact, e.g. "would unblock N recent queries") and a `confirm_token`.
2. The token is HMAC-SHA256(secret, instance + tool + canonical JSON args + expiry). It is stateless, so it works across HTTP sessions.
3. A call with the same args plus a valid token runs the change. Changed args or an expired token are rejected.

`update_gravity` sends MCP progress notifications from the streamed output and returns the last ~50 lines plus the new gravity size.

Every executed change is written to an audit log (slog): instance, tool, args, result, and the client's session ID.

## Pi-hole client behaviour
- Per-instance `*http.Client` with the configured timeout; gravity uses no timeout and relies on the ctx.
- Optional `tls_skip_verify`.
- A lazy session behind a mutex: renewed before `validity` runs out or on a 401 (one retry). `Close()` logs out.
- Typed API errors (`{"error":{"key","message","hint"}}`) that are passed through to tool results.
- A short TTL cache (30s) for clients, devices, and lists.
- SIDs, passwords, and tokens are always redacted in logs and in `config print`.

## HTTP mode security (`docs/security.md`)
- Bearer token required on `/mcp`, compared in constant time.
- Optional native TLS.
- `Origin` header check against `allowed_origins` (DNS-rebinding protection).
- Request body size limit and graceful shutdown on SIGTERM.
- `/healthz` (liveness, no auth, no data) and `/readyz` (can reach at least one Pi-hole instance).
- The default listen address is `:8765` inside the container; the docs explain how to publish it only to the LAN.
- `SECURITY.md` explains how to report vulnerabilities privately (GitHub security advisories).

## Container image and GitHub Actions
**`Dockerfile`:**
- Multi-stage; `FROM --platform=$BUILDPLATFORM golang:1.26` builds with `GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 -trimpath`. Go cross-compiles natively, so there's no slow QEMU emulation.
- Runtime image `gcr.io/distroless/static:nonroot`.
- OCI labels (`org.opencontainers.image.source`, etc.) and `ENTRYPOINT ["/pihole-mcp"]`.
- The default transport is `http` in the image (env `MCP_TRANSPORT=http`); stdio users run `docker run -i --rm -e MCP_TRANSPORT=stdio …`.
- No `HEALTHCHECK` (distroless has no shell); the docs show a compose healthcheck that uses the binary's own `pihole-mcp healthcheck` subcommand, which calls `/healthz`.
- Platforms: **linux/amd64, linux/arm64, linux/arm/v7** (older Pis).

**`.github/workflows/ci.yml`** (on push and PR):
- `gofmt` check, `go vet`, `golangci-lint`, `go test -race -cover ./...`, `govulncheck`;
- check that `docs/tools.md` is up to date;
- `docker buildx build` for all platforms without pushing.

**`.github/workflows/release.yml`** (on tag `v*.*.*`; also `workflow_dispatch`):
- Permissions: `contents: write`, `packages: write`, `id-token: write`, `attestations: write`.
- Steps: `docker/setup-buildx-action` → `docker/login-action` to `ghcr.io` with `GITHUB_TOKEN` → `docker/metadata-action` → `docker/build-push-action` with `push: true`, `provenance: mode=max`, and `sbom: true`.
- Tags: `vX.Y.Z`, `X.Y`, `X`, `latest` (stable tags only), and `sha-<short>`.
- `actions/attest-build-provenance` for the image.
- **GoReleaser** builds binaries (darwin/linux/windows × amd64/arm64, plus linux/armv7), checksums, and a changelog for the GitHub Release.
- All third-party actions are **pinned to commit SHAs**, and Dependabot keeps them current (`gomod`, `github-actions`, `docker` ecosystems).

**After the first publish**, the maintainer makes the GHCR package public in the package settings. This is a one-time manual step, documented in `CONTRIBUTING.md` / `RELEASING.md`.

## Milestones (each one self-contained for a subagent; M2–M4 can run in parallel after M1; M6 can start after M0)
- **M0 — scaffold and project hygiene:**
  - `git init` (no commits);
  - `go mod init` with the placeholder path;
  - the go-sdk v1.8.0 dependency;
  - copy this plan to `docs/PLAN.md`;
  - `CLAUDE.md`, LICENSE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG (Keep a Changelog format);
  - Makefile targets: `build test lint vuln run-stdio run-http docker docs inspector`;
  - a `main.go` that serves an empty server over stdio and HTTP.
- **M1 — config and Pi-hole client:**
  - `internal/config` (precedence, `*_FILE`, validation, redacted print) with tests;
  - `internal/pihole` and `internal/instances`;
  - `scripts/record-fixtures.sh`: read-only GETs against a live Pi-hole that **sanitize** names, IPs, and MACs before writing them to `testdata/`;
  - httptest tests, including 401 → log in again → retry;
  - `docs/api-notes.md`.
- **M2 — usage tools:** `analysis/{period,aggregate}.go` and `tools/usage.go`; MCP in-memory tests against fixture servers; multi-instance tests.
- **M3 — assessment, health, suggestions:** `analysis/{blocklists,health,suggest,adpatterns}.go`, the catalog, prompts, and resources.
- **M4 — change tools:** `confirm`, the write tools, gravity progress streaming, the audit log; tests for expiry, tampering, the disabled gate, and `allowed_tools`.
- **M5 — docs:** README (quick start for Claude Code, Claude Desktop, docker run, compose; app-password setup; security warning), `docs/configuration.md`, generated `docs/tools.md`, `deploy/` examples.
- **M6 — CI/CD:** `Dockerfile`, `.dockerignore`, `ci.yml`, `release.yml`, `.goreleaser.yaml`, Dependabot, issue and PR templates. Test with a pre-release tag (`v0.1.0-rc.1`) only after the maintainer approves pushing to GitHub.
- **M7 — reference deployment (outside this repo):** add a `pihole-mcp` service to the deployer's own Pi-hole compose file (pinned image tag, fixed address on the Pi-hole network, secrets from untracked files, `read_only`, `cap_drop: [ALL]`), deploy with the deployer's usual tooling, and leave the Pi-hole and resolver containers untouched.

## Verification
- **Local:**
  - `make test lint vuln`: unit tests (config precedence, analysis on fixtures, the client against httptest, confirm tokens) and MCP in-memory tests that call every tool against its schema;
  - `make docs` leaves no diff;
  - `docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 .` succeeds.
- **Fixture hygiene:** a CI test greps `testdata/` and fails on private IP ranges outside the documentation ranges, real-looking MACs, or anything token-shaped.
- **Live, read-only:** `go test -tags=integration ./...` with `PIHOLE_URL` and `PIHOLE_APP_PASSWORD` pointing at a real Pi-hole; every read tool is called once (read-only).
- **MCP Inspector** (`npx @modelcontextprotocol/inspector`) over stdio and over `http://<host>:8765/mcp`: list the tools, run `get_summary`, `blocked_by_device`, `assess_blocklists`, `network_health`, `suggest_improvements`.
- **Claude Code:** `claude mcp add --transport http pihole http://<host>:8765/mcp --header "Authorization: Bearer $MCP_TOKEN"`. Then ask "Which sites got blocked most this week and by which devices?"
- **Change safety (writes enabled, test domain `mcp-test.invalid`):**
  - the preview changes nothing;
  - the confirm adds the rule, and removing it also needs preview + confirm;
  - tampered or expired tokens are rejected;
  - tools outside `allowed_tools` aren't listed.
- **Release dry run:**
  - `goreleaser release --snapshot --clean` locally;
  - after the maintainer approves, an rc tag produces a multi-arch GHCR image with provenance, and `docker pull` works on the Pi (arm64).
- **Deploy check:**
  - `/healthz` and `/readyz` return 200;
  - the Pi-hole and resolver containers are untouched;
  - the web UI password fingerprint (`webserver.api.pwhash`) is unchanged.
