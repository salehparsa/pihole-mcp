# Contributing

Thanks for helping! This project handles people's DNS data and can change their network, so the bar for safety is high — but the workflow is simple.

## Setup
Go (see `go.mod`) and `make`. Docker only for image builds.

```bash
make check      # gofmt, vet, race tests, generated docs up to date
make lint vuln  # golangci-lint + govulncheck (pinned versions, fetched via `go run`)
```

## Ground rules
- **Tests never use a real Pi-hole.** Use `internal/testutil/fakepihole` and the sanitized fixtures in `testdata/` (extend the fake when you need a new endpoint). A test in `internal/testutil` rejects real-looking IPs, MACs and tokens in fixtures — keep it green; don't weaken it.
- **Never commit real network data or secrets**, including in issues and PRs. Fixture recordings (`make fixtures`) land in the git-ignored `testdata/recorded/` and must be reviewed and reduced by hand before anything is copied.
- **Change tools** must keep the two-step preview → confirm flow, be gated by `writes.enabled`, state the exact request and an impact estimate in the preview, and have tests for: preview changes nothing, confirm applies, tampered/expired tokens are rejected.
- **Don't add tools** that touch Pi-hole authentication, Teleporter, DHCP or general `/config`.
- Keep dependencies minimal; justify any new one in the PR description, and run `make licenses` so `THIRD_PARTY_LICENSES.md` stays current (only permissive licenses: MIT, BSD, Apache-2.0, ISC).
- `docs/tools.md` is generated: run `make docs` after touching tool schemas or descriptions.

## Pull requests
Small, focused PRs with tests. Fill in the template, update `CHANGELOG.md` (Keep a Changelog format), and make sure CI is green. By contributing you agree your work is licensed under Apache-2.0.

## Releasing
See [RELEASING.md](RELEASING.md).
