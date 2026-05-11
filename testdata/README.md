# testdata

This directory contains deliberately vulnerable test servers and a Go mock server
helper used to validate Batesian rules against live HTTP endpoints.

**Do not deploy any of these servers in production or on a public network.**
They are intentionally misconfigured to be exploitable.

---

## Prerequisites

```sh
pip install starlette uvicorn httpx mcp
```

---

## Server Registry

| File | Port | Rules covered |
|---|---|---|
| `a2a_vulnerable_server.py` | 9998 | `a2a-extcard-unauth-001`, `a2a-push-ssrf-001`, `a2a-session-smuggle-001`, `a2a-task-idor-001`, `a2a-jws-algconf-001`, `a2a-json-rpc-fuzz-001`, `a2a-context-orphan-001`, `a2a-peer-impersonation-001`, `a2a-delegation-escalation-001` |
| `a2a_new_rules_server.py` | 3101 | `a2a-wellknown-hostinject-001`, `a2a-artifact-tamper-001` |
| `a2a_skill_url_server.py` | 7780 | `a2a-skill-poison-001`, `a2a-url-mismatch-001` |
| `a2a_tls_capinflation_server.py` | 7782 | `a2a-tls-downgrade-001`, `a2a-capability-inflation-001` |
| `a2a_remaining_rules_server.py` | 7784 | `a2a-security-headers-001`, `a2a-registry-poison-001`, `a2a-circular-delegation-001` |
| `mcp_poison_server.py` | 8765 | `mcp-tool-poison-001` |
| `mcp_unauth_resources_server.py` | 8766 | `mcp-resources-unauth-001` |
| `mcp_oauth_dcr_server.py` | 8767 | `mcp-oauth-dcr-001` |
| `mcp_new_rules_server.py` | 3100 | `mcp-init-downgrade-001`, `mcp-cors-wildcard-001`, `mcp-prompt-unauth-001` |
| `mcp_flood_namespace_sse_server.py` | 7781 | `mcp-context-flood-001`, `mcp-tool-namespace-001`, `mcp-sse-hijack-001` |
| `mcp_injection_server.py` | 7783 | `mcp-init-instructions-inject-001`, `mcp-injection-params-001`, `mcp-ratelimit-absent-001`, `mcp-homoglyph-tool-001` |
| `mcp_oauth_audience_server.py` | 7785 | `mcp-oauth-audience-002` |

**Coverage.** All **18** bundled A2A rules (`a2a-*-001`) appear in the table
above. Of the **17** bundled MCP rules (16 `mcp-*-001` plus
`mcp-oauth-audience-002`), **14** are exercised by the Python servers listed
here. The other **3** have no standalone Python server yet; they are validated
only with `net/http/httptest` in Go unit tests:

| Rule ID | Go tests |
|---------|----------|
| `mcp-security-headers-001` | `internal/attack/mcp/security_headers_test.go` |
| `mcp-token-replay-001` | `internal/attack/mcp/token_replay_test.go` |
| `mcp-sampling-inject-001` | `internal/attack/mcp/sampling_inject_test.go` |

`mockserver.go` is a Go helper used by unit tests via `net/http/httptest`. It is
not a standalone server.

---

## Running a validation

```sh
# Start the server (in one terminal)
python testdata/a2a_vulnerable_server.py

# Run rules against it (in another terminal)
batesian scan --target http://127.0.0.1:9998 --timeout 15 -v
```

For a specific rule only:

```sh
batesian scan --target http://127.0.0.1:9998 --rule-ids a2a-push-ssrf-001 -v
```

---

## Port allocation

When adding a new test server, use the next available port in the `77xx` range
for Starlette/uvicorn servers. FastMCP servers use `87xx`. New-style servers may
use `31xx`. Document the port in this table before merging.

---

## What not to commit from this directory

The `.gitignore` excludes:
- `*.sarif` -- scan output artifacts
- `*.json` -- JSON scan results
- `*.log` -- server log files generated at runtime

Only Python source files and `mockserver.go` belong in version control.
