# Pi-hole v6 API notes

Facts this server relies on, from the OpenAPI spec Pi-hole serves at `<pihole>/api/docs`. Code against the published spec, not against one installation.

## Authentication

- `POST /api/auth {"password": "<app password>"}` → `session.sid`, `session.validity` (seconds).
- Send `X-FTL-SID: <sid>` on every call. The client renews the session shortly before it expires and, on a 401, logs in again **once** and retries.
- `DELETE /api/auth` on shutdown: sessions are limited (`webserver.api.max_sessions`) and a leaked session blocks other clients.
- App passwords have full API rights; there are no scopes.

## Endpoints used

| Purpose | Endpoint |
|---|---|
| Totals | `/stats/summary`, `/stats/database/summary?from=&until=` |
| Top lists | `/stats/(database/)top_domains?count&blocked`, `/stats/(database/)top_clients?count&blocked` |
| Upstreams | `/stats/(database/)upstreams` |
| Timelines | `/history`, `/history/database`, `/history/clients` |
| Query log | `/queries?from&until&length&cursor&domain&client_ip&client_name&upstream&type&status&dnssec&disk` |
| Lists | `GET/POST /lists`, `PUT/DELETE /lists/{address}?type=block\|allow` |
| Rules | `/domains/{allow\|deny}/{exact\|regex}[/{domain}]` |
| Lookup | `/search/{domain}` |
| Devices | `/clients`, `/network/devices`, `/groups` |
| Health | `/info/{system,sensors,ftl,host,database,version,messages}` |
| Actions | `POST /action/gravity` (streamed `text/plain`), `GET/POST /dns/blocking` |

## Checked against the spec

These points were verified against the OpenAPI spec of FTL v6.7.1 (`src/api/docs/content/specs/*.yaml`), and each has a regression test:

- **`/stats/database/summary` has a different, smaller shape** than `/stats/summary`: `{sum_queries, sum_blocked, percent_blocked, total_clients}`. It has no cache/forwarded/unique-domain counts, no per-type breakdown and no gravity info. `get_summary` therefore uses the live summary for the 24h window and the database summary otherwise (omitting, not zero-filling, what it cannot know; the gravity size always comes from the live summary). Rates in `network_health` (cache, NXDOMAIN, SERVFAIL) always use the live summary.
- **`/network/devices` returns only 10 devices** (3 addresses each) unless `max_devices` / `max_addresses` are passed; the client asks for up to 1000 / 20.
- **Timestamps in `/history` and `/info/messages` are floating point**, not integers.
- **`/queries` `cursor` is "the database ID of the most recent query to be shown"** (inclusive, newest first). The next page is requested with `cursor = oldest id returned - 1`, which is what `next_cursor` contains.
- `/stats/database/{top_domains,top_clients,upstreams}` share the live shapes and take `from`, `until`, `count`, `blocked`.

## Behaviours worth knowing

- **Live vs. database.** `/stats/*` covers the last 24h held in memory; `/stats/database/*` accepts any `from`/`until`. This server uses the database endpoints with the requested window and falls back to live stats only when the database is unavailable and the window is within 24h.
- **Query-log paging.** `/queries` returns newest first. `disk=true` reads the on-disk database beyond the 24h in memory (used automatically for older windows). Paging computes the next cursor itself (see above) and also de-duplicates by query id. Scans stop at `analysis.max_scan`.
- **Blocked statuses.** `GRAVITY`, `REGEX`, `DENYLIST`, the `*_CNAME` variants, `EXTERNAL_BLOCKED_*` and `SPECIAL_DOMAIN` (see `pihole.BlockedStatuses`).
- **Filters.** The `domain` filter supports `*` wildcards on the Pi-hole side.
- **Gravity** can run for minutes and streams plain text; the client uses no HTTP timeout for it (cancel through the MCP request). Progress lines are forwarded as MCP progress notifications.
- **Errors** have the shape `{"error":{"key","message","hint"}}` and are passed through to tool results.
- **Caching.** Lists, rules, clients and devices are cached for 30 s and invalidated by any change made through this server.
- **Not available over the API.** Disk usage and some sensors vary by platform; health checks that depend on missing data are skipped and reported under `unavailable`.

## Compatibility

FTL < 6.0 has no REST API; the server logs a warning at startup if it sees an older version. Minimum supported: **Pi-hole Core 6.0 / FTL 6.0**. Recorded/tested: Core 6.4.3, FTL 6.7.1, Web 6.4.

Refreshing test data from a live Pi-hole (read-only GETs, sanitized): `make fixtures` writes to `testdata/recorded/` for review.
