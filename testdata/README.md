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

The bundled rule set is **17 A2A + 17 MCP = 34 rules**. Every rule's primary
validation is an in-process `net/http/httptest` harness in its Go
`*_test.go` (multiple server postures: vulnerable must fire / patched / open /
benign must stay silent). The Python servers below are optional standalone
fixtures for live-validation / manual smoke testing.

| File | Port | Rules covered |
|---|---|---|
| `a2a_vulnerable_server.py` | 9998 | `a2a-extcard-unauth-001`, `a2a-push-ssrf-001`, `a2a-session-smuggle-001`, `a2a-task-idor-001`, `a2a-peer-impersonation-001`, `a2a-jws-algconf-001` |
| `a2a_new_rules_server.py` | 3101 | `a2a-wellknown-hostinject-001`, `a2a-artifact-tamper-001` |
| `a2a_multitenant_server.py` | 3102 | `a2a-multitenant-isolation-001` (two tenants; needs two `--principal`s) |
| `a2a_delegation_server.py` | 3103 | `a2a-delegation-integrity-001` (two principals; needs two `--principal`s) |
| `a2a_context_fixation_server.py` | 3104 | `a2a-context-fixation-001` (two principals; needs two `--principal`s) |
| `a2a_card_trust_server.py` | 3105 | `a2a-card-trust-001` |
| `a2a_extension_downgrade_server.py` | 3106 | `a2a-extension-downgrade-001` |
| `a2a_push_binding_server.py` | 3107 | `a2a-push-binding-001` (two principals; needs two `--principal`s) |
| `a2a_batch_bypass_server.py` | 3108 | `a2a-jsonrpc-batch-bypass-001` |
| `a2a_card_security_unenforced_server.py` | 3110 | `a2a-card-security-unenforced-001` |
| `a2a_task_cancel_server.py` | 3109 | `a2a-task-cancel-idor-001` (two principals; needs two `--principal`s) |
| `mcp_unauth_resources_server.py` | 7787 | `mcp-resources-unauth-001` |
| `mcp_oauth_dcr_server.py` | 7788 | `mcp-oauth-dcr-001` |
| `mcp_oauth_audience_server.py` | 7785 | `mcp-oauth-audience-002` |
| `mcp_new_rules_server.py` | 3100 | `mcp-init-downgrade-001`, `mcp-prompt-unauth-001`, `mcp-tools-unauth-001` |
| `mcp_session_fixation_server.py` | 7786 | `mcp-session-fixation-001` |
| `mcp_header_body_split_server.py` | 7789 | `mcp-header-body-split-001` |
| `mcp_sse_resume_replay_server.py` | 7790 | `mcp-sse-resume-replay-001` |
| `mcp_oauth_metadata_ssrf_server.py` | 7791 | `mcp-oauth-metadata-ssrf-001` |
| `mcp_secret_canary_server.py` | 7792 | `mcp-secret-canary-001` |
| `mcp_confused_deputy_server.py` | 7793 | `mcp-confused-deputy-001` |
| `mcp_dns_rebind_origin_server.py` | 7794 | `mcp-dns-rebind-origin-001` |
| `mcp_batch_bypass_server.py` | 7795 | `mcp-jsonrpc-batch-bypass-001` |
| `mcp_completion_unauth_server.py` | 7796 | `mcp-completion-unauth-001` |
| `mcp_logging_unauth_server.py` | 7797 | `mcp-logging-unauth-001` |

**Coverage.** 33 of the 34 rules have a standalone Python fixture above. The
remaining rule, `mcp-token-replay-001`, is validated only by its Go harness
(`internal/attack/mcp/token_replay_test.go`); the same is true of the per-rule
edge-case harnesses for every other rule. `mockserver.go` is a Go helper used by
unit tests via `net/http/httptest`; it is not a standalone server.

The multi-tenant and delegation fixtures exercise the chained rules: they require
two principals supplied with `--principal name=...,token=...,tenant=...` (or a
`principals:` block in `batesian.yaml`). When both `a2a-multitenant-isolation-001`
and `a2a-delegation-integrity-001` run in the same scan, the delegation rule
(a consumer) reuses a task-id the multi-tenant rule (a producer) published to the
blackboard.

> Note: some multi-rule Python servers may still carry leftover routes from rules
> that were pruned from the scanner. Only the rule IDs listed in the table above
> are part of the current rule set.

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

When adding a new test server, pick the next free port, document it in the
Server Registry table above before merging. Prefer the `77xx` band for servers
in this directory that bind with uvicorn (Starlette or FastMCP). The `31xx`
band is used for selected multi-rule MCP/A2A servers; `9998` is reserved for
the main A2A lab server. Do not reuse a port already listed in the registry.

---

## What not to commit from this directory

The `.gitignore` excludes:
- `*.sarif` -- scan output artifacts
- `*.json` -- JSON scan results
- `*.log` -- server log files generated at runtime

Only Python source files and `mockserver.go` belong in version control.
