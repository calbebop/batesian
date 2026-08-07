# testdata

This directory contains deliberately vulnerable test servers and a Go mock server
helper used to validate Batesian rules against live HTTP endpoints.

**Do not deploy any of these servers in production or on a public network.**
They are intentionally misconfigured to be exploitable.

---

## Prerequisites

```sh
pip install starlette uvicorn httpx "mcp>=2"
```

Only `mcp_unauth_resources_server.py` uses the MCP Python SDK; the rest are plain
Starlette. The SDK's v2 line is what `pip install mcp` now gives you, and it
renamed `FastMCP` to `MCPServer` with no compatibility alias, so that fixture
does not run on 1.x. The version is pinned above rather than left bare so a
future major bump is a deliberate change here instead of a fixture that stops
starting.

---

## Server Registry

The bundled rule set is **17 A2A + 19 MCP = 36 rules**. Every rule's primary
validation is an in-process `net/http/httptest` harness in its Go
`*_test.go` (multiple server postures: vulnerable must fire / patched / open /
benign must stay silent). The Python servers below are optional standalone
fixtures for live-validation / manual smoke testing.

| File | Port | Rules covered |
|---|---|---|
| `a2a_vulnerable_server.py` | 9998 | `a2a-extcard-unauth-001`, `a2a-push-ssrf-001`, `a2a-session-smuggle-001`, `a2a-peer-impersonation-001`; `a2a-task-idor-001` and `a2a-jws-algconf-001` are silent here by design (see note below) |
| `a2a_new_rules_server.py` | 3101 | `a2a-wellknown-hostinject-001`, `a2a-artifact-tamper-001` |
| `a2a_multitenant_server.py` | 3102 | `a2a-multitenant-isolation-001` (two tenants; needs two `--principal`s) |
| `a2a_delegation_server.py` | 3103 | `a2a-delegation-integrity-001` (two principals; needs two `--principal`s) |
| `a2a_context_fixation_server.py` | 3104 | `a2a-context-fixation-001` (two principals; needs two `--principal`s) |
| `a2a_card_trust_server.py` | 3105 | `a2a-card-trust-001` |
| `a2a_extension_downgrade_server.py` | 3106 | `a2a-extension-downgrade-001` |
| `a2a_push_binding_server.py` | 3107 | `a2a-push-binding-001` (two principals; needs two `--principal`s) |
| `a2a_batch_bypass_server.py` | 3108 | `a2a-jsonrpc-batch-bypass-001` |
| `a2a_task_cancel_server.py` | 3109 | `a2a-task-cancel-idor-001` (two principals; needs two `--principal`s) |
| `a2a_card_security_unenforced_server.py` | 3110 | `a2a-card-security-unenforced-001` |
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
| `mcp_task_idor_server.py` | 7798 | `mcp-task-idor-001` (two principals; needs two `--principal`s) |
| `mcp_modern_era_server.py` | 7799 | none, by design: an era-detection target, see below |
| `mcp_era_downgrade_server.py` | 7800 | `mcp-era-downgrade-001` (two postures, see below) |

**Coverage.** 35 of the 36 rules have a standalone Python fixture above. The
remaining rule, `mcp-token-replay-001`, is validated only by its Go harness
(`internal/attack/mcp/token_replay_test.go`); the same is true of the per-rule
edge-case harnesses for every other rule. `mockserver.go` is a Go helper used by
unit tests via `net/http/httptest`; it is not a standalone server.

**`mcp_modern_era_server.py` is the one server here that is not deliberately
vulnerable.** It is built on the official MCP Python SDK and speaks the
2026-07-28 revision, so era detection (`internal/attack/mcp/era.go`) can be
checked against a real modern server instead of against the specification alone.
It is not, however, a silent target: the SDK applies no authorization, so the
unauth rules fire against it on both wires and report roughly ten findings. What
this fixture proves is that the era is detected and driven correctly, not that a
scan comes back clean. `.github/workflows/mcp-era-watch.yml` starts it weekly and
runs the integration-tagged tests in `internal/attack/mcp/era_live_test.go`
against it:

```sh
python testdata/mcp_modern_era_server.py &
BATESIAN_LIVE_MCP_ENDPOINT=http://127.0.0.1:7799/mcp \
  go test -tags=integration -run TestDetectEra_Live ./internal/attack/mcp/
```

Because the SDK serves both eras from one server, it also answers the 2025-era
`initialize` handshake, which is why the existing rules still work against
current deployments.

**`mcp_era_downgrade_server.py` takes a posture argument**, defaulting to
`vulnerable`:

```sh
python testdata/mcp_era_downgrade_server.py vulnerable      # rule must fire
python testdata/mcp_era_downgrade_server.py discovery-only  # rule must stay silent
```

`discovery-only` serves one wire and gates nothing, while still answering
`server/discover` (which every server implements whatever era it serves) with a
`supportedVersions` list that names only handshake-era revisions. It is the
posture a server built on the Go SDK has when `StreamableHTTPOptions.Stateless`
is left false. It exists because era detection used to read "discovery answered"
as "the modern wire is served", which turned that server's `400 Bad Request:
protocol version "2026-07-28" is only supported on stateless HTTP servers` into
the refused half of an authorization asymmetry and produced a critical
`mcp-era-downgrade-001` finding against a target with no authorization at all.

The multi-tenant and delegation fixtures exercise the chained rules: they require
two principals supplied with `--principal name=...,token=...,tenant=...` (or a
`principals:` block in `batesian.yaml`). When both `a2a-multitenant-isolation-001`
and `a2a-delegation-integrity-001` run in the same scan, the delegation rule
(a consumer) reuses a task-id the multi-tenant rule (a producer) published to the
blackboard.

> Note: some multi-rule Python servers may still carry leftover routes from rules
> that were pruned from the scanner. Only the rule IDs listed in the table above
> are part of the current rule set.

**A rule staying silent against its fixture is not always a fixture bug.** Two
rules on `a2a_vulnerable_server.py` are silent by design, because the fixture
does not exhibit what they test for:

- `a2a-task-idor-001` requires authentication to be enforced on task creation, so
  that reading a task back without credentials demonstrates broken *authorization*
  rather than absent *authentication*. This fixture enforces no authentication at
  all, so the rule's discriminator correctly suppresses the finding. That
  no-auth exposure is `a2a-peer-impersonation-001`'s territory, and it does fire.
- `a2a-jws-algconf-001` analyses JWS signatures on the agent card. This fixture
  deliberately serves an unsigned card, so there is nothing to analyse.

When adding a fixture, confirm the rule actually fires against it rather than
assuming coverage from the registry table. `a2a-session-smuggle-001` was listed
here for a long time while the fixture returned a hardcoded task history that
could never contain the scanner's marker, so the rule could never confirm the
injection and always reported nothing.

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
in this directory that bind with uvicorn (Starlette or the MCP SDK). The `31xx`
band is used for selected multi-rule MCP/A2A servers; `9998` is reserved for
the main A2A lab server. Do not reuse a port already listed in the registry.

---

## What not to commit from this directory

The `.gitignore` excludes:
- `*.sarif` -- scan output artifacts
- `*.json` -- JSON scan results
- `*.log` -- server log files generated at runtime

Only Python source files and `mockserver.go` belong in version control.
