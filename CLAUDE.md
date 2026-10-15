# CLAUDE.md — pihole-mcp

MCP server (Go) for Pi-hole v6. The full plan is in `docs/PLAN.md`; the reasons behind the design are in `docs/security.md` and `docs/api-notes.md`.

## Hard rules
- **Never** touch the Pi-hole web UI password or auth config, Teleporter, DHCP, or general `/config` writes. No tool for them may be added.
- **No git commits or pushes** unless the maintainer asks. `git init` is fine.
- **No personal data in the repo.** Test fixtures in `testdata/` are sanitized: IPs in `192.0.2.0/24` or `2001:db8::/32`, MACs `00:00:5e:00:53:xx`, made-up names/domains, no secrets. `internal/testutil/fixtures_test.go` enforces this. Regenerate with `scripts/gen-testdata.py`; recordings from a live Pi-hole go to the git-ignored `testdata/recorded/` and must be reviewed.
- **Nothing deployment-specific is hardcoded** (IPs, host names, time zone, upstreams). That belongs in the user's compose file / `.env`.
- Tests must never need or touch a real Pi-hole. Live checks are behind `-tags=integration` and are read-only.
- Change tools stay two-step (preview → `confirm_token`), gated by `writes.enabled`, and audited.

## Layout
```
cmd/pihole-mcp/        main: serve (default), config validate|print, docs, healthcheck, version
internal/config/       load/merge/validate (flags > env > yaml > defaults, *_FILE secrets)
internal/pihole/       typed v6 API client (no MCP knowledge)
internal/instances/    name → client registry
internal/analysis/     pure functions → Findings (heavily unit-tested)
internal/confirm/      HMAC preview/confirm tokens
internal/tools/        MCP tools, prompts, resources (thin wrappers) + docs generator
internal/server/       HTTP transport: bearer auth, Origin check, /healthz, /readyz
internal/catalog/      embedded curated block-list catalog
internal/testutil/     fakepihole: in-memory Pi-hole API served from testdata/
```

## Commands
```
make check        # fmt, vet, race tests, docs/tools.md up to date
make docs         # regenerate docs/tools.md (CI fails if stale)
make lint vuln    # golangci-lint, govulncheck
make docker       # local image;  make docker-multiarch  # amd64+arm64+armv7, not pushed
make integration  # READ-ONLY live tests (PIHOLE_URL, PIHOLE_APP_PASSWORD)
```

## Adding a tool
1. Read tool: add input/output structs (with `jsonschema` tags) and a method on `Deps` in `internal/tools`, register with `addRead`. Put logic that can be pure in `internal/analysis`.
2. Change tool: implement `writeArgs` and a `plan` function (validate → preview text → `apply`), register with `addWrite` in `registerWrites`. Preview must show the exact request, current/proposed state and an impact estimate.
3. Add tests against `fakepihole` (extend the fake if an endpoint is missing), run `make docs`, update `CHANGELOG.md`.
