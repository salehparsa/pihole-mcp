## What and why

## Checklist
- [ ] `make check` passes (fmt, vet, tests, `docs/tools.md` up to date)
- [ ] New or changed tools have tests that run against the fake Pi-hole (`internal/testutil/fakepihole`)
- [ ] Any change tool keeps the two-step preview → confirm flow and is gated by `writes.enabled`
- [ ] No secrets or real network data in code, tests or `testdata/` (fixtures are sanitized: `192.0.2.x`, fake MACs)
- [ ] `CHANGELOG.md` updated
