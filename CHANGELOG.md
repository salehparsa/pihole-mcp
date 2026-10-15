# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- MCP server for Pi-hole v6 with stdio and Streamable HTTP transports (bearer token, Origin check, `/healthz`, `/readyz`).
- Usage tools: `get_summary`, `top_domains`, `top_clients`, `blocked_by_device`, `client_activity`, `query_timeline`, `search_queries`, `explain_domain`, `list_devices`, `list_instances`.
- Block-list and health tools: `list_blocklists`, `list_domain_rules`, `assess_blocklists`, `network_health`, `get_pihole_messages`, `suggest_improvements`.
- Opt-in change tools with two-step preview/confirm tokens and an audit log: `add_blocklist`, `remove_blocklist`, `set_blocklist_enabled`, `add_domain_rule`, `remove_domain_rule`, `update_gravity` (streams progress), `set_blocking`.
- Prompts (`weekly_report`, `assess_blocklists`, `investigate_device`, `improve_adblocking`) and resources (block-list catalog, instance status).
- Multi-instance support, configuration by flags/env/YAML with `*_FILE` secrets, `config validate|print`.
- `NOTICE`, `THIRD_PARTY_LICENSES.md` (also shipped in the image and release archives) and a README disclaimer (unofficial, no warranty).
- Multi-arch container image (amd64, arm64, armv7) and release automation to GHCR.
