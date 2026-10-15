# Configuration

Precedence: **flags > environment variables > YAML file > defaults.** Pass the file with `--config FILE` or `PIHOLE_MCP_CONFIG`.

Every secret (app password, MCP token, confirm secret) can be given inline *or* as a file — the `*_FILE` variants work with Docker/Kubernetes secrets. Setting both an inline value and its file for the same secret is an error.

```bash
pihole-mcp config validate   # checks everything, prints a one-line summary
pihole-mcp config print      # effective configuration, secrets shown as ***
```

Validation fails fast, with a message that names the problem: no instance, unparsable URL, missing password, http transport without a token, both a password and a password file, `confirm_ttl <= 0`, unknown time zone, …

## Quick reference

| YAML | Environment | Flag | Default | Notes |
|---|---|---|---|---|
| `instances[0].url` | `PIHOLE_URL` | | | Env shortcut configures the first instance (named `default`) |
| `instances[].password` / `password_file` | `PIHOLE_APP_PASSWORD` / `PIHOLE_APP_PASSWORD_FILE` | | | App password |
| `instances[].tls_skip_verify` | `PIHOLE_TLS_SKIP_VERIFY` | | `false` | Only for self-signed Pi-hole HTTPS |
| `instances[].timeout` | | | `10s` | Per request; gravity updates have none |
| `instances[].name` | | | `default` (first) | Required for 2nd+ instances; the `instance` tool argument |
| `server.transport` | `MCP_TRANSPORT` | `--transport` | `stdio` | `stdio` or `http` (the container image defaults to `http`) |
| `server.listen` | `MCP_LISTEN` | `--listen` | `:8765` | http only |
| `server.path` | `MCP_PATH` | | `/mcp` | |
| `server.auth_token` / `auth_token_file` | `MCP_TOKEN` / `MCP_TOKEN_FILE` | | | **Required** for http |
| `server.tls_cert_file`, `tls_key_file` | `MCP_TLS_CERT_FILE`, `MCP_TLS_KEY_FILE` | | | Set both or neither |
| `server.allowed_origins` | `MCP_ALLOWED_ORIGINS` (comma separated) | | `[]` | Browser `Origin`s permitted. Native clients send none. With an empty list every browser Origin is refused |
| `writes.enabled` | `PIHOLE_MCP_ALLOW_WRITES` | | `false` | Registers the change tools |
| `writes.confirm_secret` / `confirm_secret_file` | `PIHOLE_MCP_CONFIRM_SECRET` / `_FILE` | | random per process | Set it if you run several replicas or want tokens to survive a restart |
| `writes.confirm_ttl` | `PIHOLE_MCP_CONFIRM_TTL` | | `5m` | |
| `writes.allowed_tools` | `PIHOLE_MCP_ALLOWED_TOOLS` (comma separated) | | `[]` (all) | Allowlist of change tools, e.g. `add_domain_rule,update_gravity` |
| `analysis.timezone` | `PIHOLE_MCP_TIMEZONE`, `TZ` | | `UTC` | IANA zone for dates, hour-of-day and day buckets |
| `analysis.default_period` | | | `24h` | |
| `analysis.max_scan` | | | `50000` | Max query-log entries examined per call |
| `analysis.stale_list_days` | | | `7` | |
| `analysis.high_block_ratio` | | | `0.5` | Devices above this share of blocked queries are flagged |
| `analysis.ad_patterns_file` | | | | One regex per line; start the file with `# replace-defaults` to replace the built-in heuristics |
| `analysis.catalog_file` | | | | JSON file replacing the embedded block-list catalog (same shape as `internal/catalog/blocklists.json`) |
| `log.level` | `LOG_LEVEL` | | `info` | `debug`, `info`, `warn`, `error` |
| `log.format` | `LOG_FORMAT` | | `text` | `text` or `json`. Logs go to stderr (stdout carries the stdio protocol) |

The environment variables `PIHOLE_URL`, `PIHOLE_APP_PASSWORD(_FILE)` and `PIHOLE_TLS_SKIP_VERIFY` always apply to the **first** instance; define additional Pi-holes in the YAML file.

## Several Pi-holes

```yaml
instances:
  - name: home
    url: http://192.0.2.2
    password_file: /run/secrets/home_pw
  - name: cabin
    url: https://cabin.example.net
    password_file: /run/secrets/cabin_pw
```

Every tool takes an optional `instance`; the first is the default. `list_instances` shows each one's FTL version and blocking state.

## Time handling

`period` ("1h", "24h", "7d", "2w", "30d") looks back from now. `from` / `until` take RFC 3339 timestamps, or a bare date (`2025-01-31`) interpreted in `analysis.timezone`. Reported times are rendered in that zone.

Statistics use Pi-hole's long-term database for any window; if the database is unavailable and the window is within the live 24 hours the in-memory statistics are used and the result's `source` says so.

## Ad/tracker heuristics

`suggest_improvements` flags frequently *allowed* domains that look like ad or tracking endpoints (`ads.`, `telemetry.`, `metrics.`, `pixel.`, well-known ad networks, …). The patterns are deliberately conservative hints, and an explicit allow rule is mentioned in the finding. Extend or replace them with `analysis.ad_patterns_file`:

```
# replace-defaults        <- optional first line: use only the patterns below
^beacon[0-9]*\.
(^|\.)adservice\.example$
```
