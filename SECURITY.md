# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** using GitHub's *Report a vulnerability* button (Security → Advisories) on this repository. Do not open a public issue. Include the version (`pihole-mcp version`), how you run it (stdio/http), and steps to reproduce; **do not include real app passwords, tokens or network data**.

You can expect an acknowledgement within a few days and a fix or mitigation plan once the report is confirmed. We credit reporters unless they prefer otherwise.

## Scope
In scope: authentication/authorization of the HTTP transport, the preview/confirm mechanism, secret handling and redaction, anything that lets a client change Pi-hole when writes are disabled, or reach data/endpoints it should not.

Out of scope: the Pi-hole app password having full API rights (a Pi-hole property — see [docs/security.md](docs/security.md)), and exposure caused by publishing the port to untrusted networks without TLS.

## Supported versions
Only the latest release receives fixes while the project is pre-1.0.
