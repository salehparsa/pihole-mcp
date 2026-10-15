# Releasing

Releases are cut by pushing a semver tag; GitHub Actions does the rest (`.github/workflows/release.yml`).

1. Update `CHANGELOG.md` (move *Unreleased* to the new version) and merge to the default branch.
2. Tag and push: `git tag v0.1.0 && git push origin v0.1.0` (use `v0.1.0-rc.1` to rehearse; pre-releases don't get `latest`/`X`/`X.Y` tags).
3. The workflow:
   - builds `linux/amd64`, `linux/arm64`, `linux/arm/v7` and pushes `ghcr.io/<owner>/pihole-mcp` tagged `vX.Y.Z`, `X.Y`, `X`, `latest` (stable only) and `sha-<short>`, with provenance (`mode=max`), an SBOM and a build attestation;
   - runs GoReleaser to attach binaries (darwin/linux/windows × amd64/arm64, linux/armv7), checksums and a changelog to the GitHub Release.
4. **After the very first publish** (one-time, manual): in GitHub → *Packages* → `pihole-mcp` → *Package settings* → change visibility to **Public**, so `docker pull` works without logging in. Also link the package to the repository if it isn't already.
5. Verify: `docker pull ghcr.io/<owner>/pihole-mcp:<version>` on an arm64 machine and `docker run --rm ghcr.io/<owner>/pihole-mcp:<version> version`.

Local dry runs: `make docker-multiarch` and `go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean`.

All third-party actions are pinned to commit SHAs; Dependabot proposes updates.
