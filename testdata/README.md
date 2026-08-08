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

Two fixtures use the MCP Python SDK, `mcp_unauth_resources_server.py` and
`mcp_modern_era_server.py`; the rest are plain Starlette. Both import
`mcp.server.mcpserver.MCPServer`, so both need the v2 line: it renamed `FastMCP`
to `MCPServer` with no compatibility alias and neither fixture runs on 1.x. The
version is pinned above rather than left bare so a future major bump is a
deliberate change here instead of a fixture that stops starting.

If either fails to start with `ModuleNotFoundError: No module named
'mcp.server.mcpserver'`, the installed `mcp` is 1.x. Check with
`python -c "import importlib.metadata as m; print(m.version('mcp'))"`. This is
worth knowing before a sweep: a fixture that does not bind measures nothing, and
a run that treats it as a clean result is reporting coverage it does not have.

---

## Server Registry

The bundled rule set is **17 A2A + 20 MCP = 37 rules**. Every rule's primary
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
| `mcp_oauth_audience_server.py` | 7785 | `mcp-oauth-audience-002` (four sub-paths, one per bug class; target each, not the root) |
| `mcp_new_rules_server.py` | 3100 | `mcp-prompt-unauth-001`, `mcp-tools-unauth-001`; `mcp-init-downgrade-001` needs the `downgrade` posture, see below |
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
| `mcp_task_idor_server.py` | 7798 | `mcp-task-idor-001` (two principals; needs two `--principal`s; two postures, see below) |
| `mcp_modern_era_server.py` | 7799 | none, by design: an era-detection target, see below |
| `mcp_era_downgrade_server.py` | 7800 | `mcp-era-downgrade-001` (two postures, see below) |
| `mcp_large_body_server.py` | 7801 | the unauth family at responses past the body read limit, see below |
| `mcp_transient_failure_server.py` | 7802 | the unauth family when a probe fails without refusing, see below |
| `mcp_session_as_credential_server.py` | 7803 | `mcp-session-as-credential-001` (needs `--token tok-a`; four postures, see below) |

**Coverage.** 36 of the 37 rules have a standalone Python fixture above, and each
of those was checked by actually running it rather than by reading this table. The
remaining rule, `mcp-token-replay-001`, is validated only by its Go harness
(`internal/attack/mcp/token_replay_test.go`); the same is true of the per-rule
edge-case harnesses for every other rule. `mockserver.go` is a Go helper used by
unit tests via `net/http/httptest`; it is not a standalone server.

A registry row is a claim, and claims rot. Three things make a fixture look broken
when it is not, so check them before concluding a rule has regressed:

- **Tokens.** The multi-principal fixtures expect `tok-a` and `tok-b`
  specifically, not arbitrary names.
- **Target.** The OAuth fixtures (`mcp_oauth_dcr_server.py`,
  `mcp_oauth_metadata_ssrf_server.py`, `mcp_confused_deputy_server.py`) are
  scanned at the root, not at `/mcp`. `mcp_oauth_audience_server.py` is the
  opposite: each bug class lives at its own sub-path, so the target must name the
  endpoint (`http://127.0.0.1:7785/vulnerable-substring/mcp` and so on). Scanning
  its root correctly reports "not tested".
- **Audience case.** `mcp_oauth_audience_server.py` advertises
  `https://API.example.com/mcp`, mixed case on purpose so the case-fold endpoint
  has something to vary. Either omit `--audience-claim` and let RFC 9728 discovery
  supply it, or pass that exact value. Passing an all-lowercase spelling used to
  silently disable the substring and case-fold probes, because every probe is built
  from the value given and RFC 7519 compares the claim exactly; the rule now
  reports "not tested" and names both values instead.
- **Postures.** Several fixtures need a non-default argument, listed above.

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

**`mcp_large_body_server.py` is a size test, not a new vulnerability.** It has no
authentication at all, so it should produce the same findings any open server
does. What it varies is response size: every listing and read is padded past the
scanner's body read limit, which is what a real server does without trying once it
has a few hundred tools or a config file worth reading.

```sh
python testdata/mcp_large_body_server.py            # ~1.33 MB responses
python testdata/mcp_large_body_server.py 7801 8     # ~20 KB, the control
```

Both invocations must produce the same findings. They did not: the read limit was
1 MB and truncated silently, the truncated JSON-RPC result was unparseable, and
rules that treat an unparseable probe the same as a refused one reported those
surfaces clean. The large server gave 1 finding where the small one gave 7, so a
server could hide every unauthenticated-access finding by being large. If the two
invocations ever disagree again, a body is being truncated somewhere.

**`mcp_task_idor_server.py` takes a posture argument**, defaulting to `vulnerable`:

```sh
python testdata/mcp_task_idor_server.py              # creation and reads authenticated
python testdata/mcp_task_idor_server.py create-open  # only reads authenticated
```

Both postures must produce the same three findings. The rule suppresses itself when
a server authenticates nothing, because that is `mcp-tools-unauth-001`'s failure
rather than an IDOR, but it used to decide that from task creation alone. The
`create-open` posture leaves a task-augmented `tools/call` open while `tasks/get`,
`tasks/result` and `tasks/list` all require a Bearer token and none of them are
scoped to the creator. That is a real authorization boundary on the exact surface
the rule tests, and the scanner reported the server clean. Run both postures when
touching the discriminator: agreement is the property under test.

**`mcp_new_rules_server.py` takes a posture argument**, defaulting to `open`:

```sh
python testdata/mcp_new_rules_server.py            # prompt-unauth + tools-unauth
python testdata/mcp_new_rules_server.py downgrade  # mcp-init-downgrade-001
```

`mcp-init-downgrade-001` needs its own posture because accepting an old protocol
version is not the bug. Version negotiation permits a server to honour a supported
older revision, so the rule requires an asymmetry: resources/list REJECTED under
the modern version but GRANTED under the pre-auth 2024-11-05. The `open` posture
enforces nothing and therefore grants both, which is
`mcp-resources-unauth-001`'s finding rather than a downgrade, and the rule
correctly stays silent.

This row claimed `mcp-init-downgrade-001` for a long time while the rule could not
possibly fire against the fixture, so a critical-severity rule had no standalone
fixture at all and nobody could tell from the table. That is the failure the note
below about confirming a rule actually fires is warning about.

**`mcp_transient_failure_server.py` separates a failure from a refusal.** It has
no authentication, and selects how its listing methods answer:

```sh
python testdata/mcp_transient_failure_server.py 7802 ok    # findings
python testdata/mcp_transient_failure_server.py 7802 401   # clean, auth enforced
python testdata/mcp_transient_failure_server.py 7802 502   # not tested
```

All three must differ. They did not: the rules gated on
`if err != nil || !resp.IsSuccess() { return nil }`, so a gateway 502 was
indistinguishable from a 401 and both reported the surfaces clean. An operator
could not tell "this server enforces auth" from "the scanner could not tell". If
the 401 and 502 runs ever agree again, that conflation is back.

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

**`mcp_session_as_credential_server.py` takes a posture argument**, defaulting to
`vulnerable`, and needs `--token tok-a`:

```sh
python testdata/mcp_session_as_credential_server.py vulnerable             # rule must fire
python testdata/mcp_session_as_credential_server.py open-handshake         # rule must fire
python testdata/mcp_session_as_credential_server.py patched                # rule must stay silent
python testdata/mcp_session_as_credential_server.py session-presence-auth  # rule must stay silent
```

All four are stateful and reject a session id they never issued, which is what
lets the rule attribute a success to the issued id. `open-handshake` is the same
bug as `vulnerable` on a server that gates nothing at `initialize`: the session
remembers who opened it, and that memory authorizes later calls that carry no
credential. It exists because an open handshake is not the same thing as no
authorization, and a rule that treats it as such reports nothing here.
`patched` authenticates every request on its own credential.
`session-presence-auth` authenticates nothing but
demands a session id on every non-initialize request, so a stripped request is
refused for session reasons rather than credential ones; it is the shape of the
official MCP C# SDK's stateful sample, which this rule reported as vulnerable
until the anonymous-handshake control was added. Without `--token` the rule
reports inconclusive against all three, since it cannot ask whether a session id
substitutes for a credential it was never given.

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

**`a2a-peer-impersonation-001` reports "not tested" against most fixtures here, and
that is correct.** The rule forges a JWT and asks whether the server accepts it. To
mean anything, the forged token has to carry the issuer the target actually trusts:
a server that checks the issuer against an allowlist before verifying the signature
refuses an unknown issuer with a 401, which looks exactly like a server that
verified the signature and rejected it. The rule therefore discovers the issuer from
RFC 9728 protected-resource metadata or from an `openIdConnect` / `oauth2`
securityScheme in the agent card. Six of the eleven A2A fixtures publish neither and
refuse the forged token, so the rule cannot attribute the refusal and says so
instead of reporting clean. Only `a2a_card_security_unenforced_server.py` publishes
security schemes; the four fixtures where the rule fires do so because they accept
the token, which needs no issuer at all.

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
