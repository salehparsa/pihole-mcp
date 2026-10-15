# Security

## Threat model

`pihole-mcp` sits between an AI agent and your Pi-hole. The things worth protecting:

| Asset | Risk | Mitigation |
|---|---|---|
| Pi-hole app password (full API rights; Pi-hole has no scopes) | Leak → total control of your DNS | Read from a file/secret, never logged, redacted in `config print`; the Pi-hole API session id is never exposed |
| MCP bearer token (http) | Leak → anyone can use the tools | Constant-time comparison; required for http; use a long random value |
| Your DNS history | Privacy: reveals browsing | Read tools are the whole point — put the server behind your trust boundary (LAN only), and treat the MCP client as trusted with that data |
| Pi-hole configuration | A prompt-injected or confused agent changes blocking | Writes **off by default**; allowlist; two-step preview/confirm; audit log |

### Prompt injection

Domain names, list comments and host names come from the network and can contain text that tries to instruct the agent. The server treats all of it as data and never executes it, but the *agent* may read it. This is why changes need a preview and a token, and why well-behaved clients should show the preview to a human before confirming.

## Change safety

- Change tools exist only when `writes.enabled` is true, and only those in `writes.allowed_tools` if that is set. They are re-checked at call time.
- A call without `confirm_token` changes nothing. It returns the exact request, current vs. proposed state, an impact estimate, and a token: `HMAC-SHA256(secret, expiry | instance | tool | canonical arguments)`.
- Executing requires the *same* instance, tool and arguments within `confirm_ttl`. Anything else is rejected. Tokens are stateless, so they work across HTTP sessions; set `writes.confirm_secret` so they also survive restarts and work across replicas.
- Never touched by design: web UI password and auth configuration, Teleporter, DHCP, general `/config` writes.
- Every applied change is logged (`event=audit`) with instance, tool, arguments, result and the MCP session id. Secrets and tokens are not logged.
- Over-broad regex rules (matching everything) are refused at preview time.

## HTTP transport

- Bearer token required on the MCP path; the server will not start in http mode without one.
- `Origin` is checked against `server.allowed_origins` (DNS-rebinding protection); with the default empty list any browser origin is refused. Native MCP clients send no Origin and are unaffected.
- Request bodies are limited to 1 MiB. Graceful shutdown on SIGTERM/SIGINT, and the Pi-hole API sessions are logged out.
- `/healthz` (liveness, no auth, no data) and `/readyz` (a Pi-hole is reachable). Neither returns details.
- The container listens on `:8765`. **Publish it on a LAN address, not `0.0.0.0` on an exposed host**, and use TLS (native via `MCP_TLS_CERT_FILE`/`MCP_TLS_KEY_FILE`, or a reverse proxy) if the network is not fully trusted: the bearer token travels in a header.

## Hardening checklist

- [ ] Dedicated app password for this server (revoke it in the Pi-hole UI to cut access).
- [ ] Secrets via `*_FILE`, not command-line arguments or committed env files.
- [ ] `writes.enabled=false` unless you need changes; otherwise set `writes.allowed_tools` to the minimum.
- [ ] `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges` on the container (see the compose example).
- [ ] Pin the image to a version tag or digest; the release workflow publishes provenance and an SBOM.
- [ ] Don't expose the port to the internet.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
