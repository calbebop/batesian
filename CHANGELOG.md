# Changelog

## Unreleased

Changes on `main` since v1.7.0 are planned for v1.8.0. The catalog has 48 rules, up from 39: 19 A2A and 29 MCP.

### New rules

- A2A push callback authentication: `a2a-push-callback-auth-001`.
- MCP authorization and exposure: `mcp-origin-prefix-bypass-001`, `mcp-scope-confusion-001`, `mcp-shadow-surface-001`, and `mcp-vulnerable-version-001`.
- MCP tools and tasks: `mcp-param-header-mismatch-001`, `mcp-task-id-entropy-001`, `mcp-tool-param-traversal-001`, and `mcp-tool-poisoning-001`.

### Protocol coverage

- MCP probes select the stateless 2026-07-28 wire when available, use negotiated versions on legacy requests, and reject incomplete or mismatched responses.
- A2A probes validate Agent Cards and cover v1.0 and v0.3 JSON-RPC and REST paths for task, push notification, and extended-card checks.

### Results and operation

- JSON reports now have a schema version and per-rule outcomes. SARIF includes coverage status, evidence, stable fingerprints, and finding-specific severity.
- Findings require observed evidence for confirmed confidence. Unobserved callbacks and incomplete inventories are reported as incomplete, not clean.
- CLI output redacts configured secrets and escapes terminal control characters. Configuration discovery can be disabled, and `init` will not overwrite an existing file.
- The release pipeline verifies archives, CycloneDX SBOMs, checksums, signatures, and provenance before publishing.

## v1.7.0

Introduced MCP 2026-07-28 support, four rules, and scheduled validation against third-party implementations. See the [v1.7.0 release notes](https://github.com/calbebop/batesian/releases/tag/v1.7.0).
