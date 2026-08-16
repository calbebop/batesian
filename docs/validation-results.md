# Validation Results

Every Batesian rule ships with an in-process `httptest` harness and, for most
rules, a deliberately vulnerable Python fixture in [`testdata/`](../testdata/README.md).
Those are necessary but not sufficient: a rule validated only against a fixture
its own author wrote is largely a test of that author's assumptions. Fixtures
serve JSON-RPC exactly where the executor expects it, answer with exactly the
error codes the executor checks for, and advertise exactly the capabilities the
rule gates on.

This document records what happens when the rules are pointed at **third-party
reference implementations** instead: servers written by the protocol maintainers,
with no knowledge of Batesian.

The fixture and third-party validation are now automated in CI.
`.github/workflows/validation.yml` runs nightly and on dispatch, and exercises the
A2A false-positive gate against the auth-enforcing secured-agent fixture; the MCP
property fixtures (probe-honesty, log opt-in, body size, session-as-credential);
a third-party FastMCP server for MCP false-positive and true-positive coverage;
and the OAuth DCR cleanup-and-report-leftovers gate. The per-rule outcomes below
are the manual runs that established those gates.

---

## Why this matters

Running against reference implementations has repeatedly found defects that the
fixture harnesses could not, because the fixtures encoded the same assumption the
executor did. Each of the following was a real bug in Batesian, found only by
running against third-party code:

| Defect | How it surfaced | Fix |
|---|---|---|
| A2A rules assumed the JSON-RPC endpoint was at the target root | The reference agent mounts it at `/a2a/jsonrpc`; every A2A rule POSTed to `/`, got 404, and the scan reported "appears clean" | Endpoint discovery from the agent card ([#79](https://github.com/calbebop/batesian/pull/79)), plus honest inconclusive reporting ([#80](https://github.com/calbebop/batesian/pull/80)) and JSON-RPC interface selection ([#81](https://github.com/calbebop/batesian/pull/81)) |
| `completion/complete` probe used a single-character argument value | Prefix-matching servers filtered it out, so a server that *was* disclosing values returned nothing and the rule stayed silent | Probe with an empty value, which asks a prefix matcher for its whole candidate set ([#83](https://github.com/calbebop/batesian/pull/83)) |
| `logging/setLevel` probe only accepted `-32602` as proof of dispatch | The reference server answers an invalid level with `-32603` from an internal validation path, so a genuine finding was missed | Treat any non-auth, non-method-not-found error as dispatch past the auth layer ([#86](https://github.com/calbebop/batesian/pull/86)) |

Two of these three were **false negatives**: the rule silently reported nothing
against a server that genuinely exhibited the condition. A false negative in a
security scanner is worse than a noisy one, and none of them were reachable from
a self-authored fixture.

A **negative control** is what the exercise was missing for a long time, and adding
one found a third false negative. Running against an agent built to be vulnerable in
one specific way, rather than against an open agent, showed
`a2a-delegation-integrity-001` reporting that a delegated task's chain of custody
held while the wrong principal was demonstrably continuing it. Its oracle compared
identifiers in the reply, and read only the flat envelope: in A2A v1.0 a send-style
reply is a `SendMessageResponse`, a protobuf oneof, so the Task arrives nested under
`result.task`, while `GetTask` returns it flat. The read checks were therefore fine
and the continuation check silently never matched. An open agent could not have
surfaced it, because the rule's own discriminator suppresses on a server with no
authorization at all.

The same exercise has also caught a false positive before it shipped.
`mcp-session-as-credential-001` passed every posture in its own harness, then
reported the official MCP C# SDK's stateful sample as vulnerable. That sample
implements no authorization at all, but requires an `Mcp-Session-Id` on every
non-initialize request, so it refused each of the rule's unauthenticated controls
for session reasons rather than credential ones and the controls read those
refusals as an enforced authorization boundary. The rule now settles the question
with an anonymous handshake before drawing any conclusion, and
`testdata/mcp_session_as_credential_server.py session-presence-auth` reproduces
that server's shape so the regression stays covered.

---

## MCP: `@modelcontextprotocol/server-everything`

The reference MCP server maintained by the Model Context Protocol project,
exercising the full capability surface (tools, prompts, resources, logging,
completions).

**Target:** `@modelcontextprotocol/server-everything` 2026.7.4, Streamable HTTP
transport, `http://127.0.0.1:3120`
**Command:** `batesian scan --target http://127.0.0.1:3120 --timeout 20`

### Result

```
Scan Results (10 finding(s))    critical 0 · high 6 · medium 4
```

| Rules | Count |
|---|---|
| MCP rules that fired | 6 of 17 (10 findings) |
| MCP rules that ran and reported nothing | 11 of 17 |
| MCP rules skipped as unreachable | 0 |
| A2A rules that fired against an MCP server | **0** |

### What fired

| Rule | Severity | Finding |
|---|---|---|
| `mcp-dns-rebind-origin-001` | high | Origin header not validated |
| `mcp-resources-unauth-001` | high | `resources/list` returned 7 resources; resource content readable |
| `mcp-tools-unauth-001` | high / medium | `tools/call` dispatch reachable; `tools/list` returned 13 tools |
| `mcp-prompt-unauth-001` | high / medium | Prompt content readable; `prompts/list` returned 4 templates |
| `mcp-completion-unauth-001` | high / medium | Suggestion values disclosed; endpoint reachable |
| `mcp-logging-unauth-001` | medium | `logging/setLevel` reachable |

**Honest framing.** `server-everything` is a reference implementation with no
authorization layer by design. The unauthenticated-access findings above
accurately describe its behavior, but they are expected for a demo server and
should not be read as defects in it. What they demonstrate is that the rules
correctly identify real protocol conditions in code Batesian's authors did not
write.

One finding is different in kind. **Missing Origin validation is a genuine spec
violation**, not an artifact of the server having no auth. The Streamable HTTP
transport requires servers to validate `Origin` and reject a foreign one with
`403`, specifically because these servers bind to localhost and a browser can be
induced to reach them via DNS rebinding. The check is a two-step control:

```
endpoint: http://127.0.0.1:3120/mcp
baseline initialize (no Origin): accepted
initialize with Origin https://dns-rebind.batesian.invalid: accepted (should be HTTP 403)
```

The baseline proves the endpoint is live and responsive; the second request
differs only in the `Origin` header. This is the class behind CVE-2025-49596
(MCP Inspector RCE).

Hand-verified findings, confirmed by probing the server directly rather than
trusting the scanner's own report:

```
completion/complete → prompt "completable-prompt", argument "department"
  values (4): [Engineering Sales Marketing Support]

logging/setLevel with a valid level → {"result":{}}   (unauthenticated)
logging/setLevel with an invalid level → -32603
```

### What correctly stayed silent

This is the more informative half. Eleven MCP rules ran against a server with
**no authentication whatsoever** and reported nothing, because each carries an
explicit precondition or discriminator that a naive implementation would lack:

| Rule | Why it declined to report |
|---|---|
| `mcp-token-replay-001` | Gates on OAuth metadata being present. The server publishes none, so there is no token-validation layer to test. A rule that simply checked "was my forged token accepted?" would have fired here, since a server with no auth accepts everything. |
| `mcp-init-downgrade-001` | Requires the modern-version session to be *rejected* and the legacy one accepted. Both succeed here, which means no auth at all rather than a downgrade bypass. |
| `mcp-session-fixation-001` | Control requires an un-initialized session id to be rejected. It is accepted, so the server tracks no sessions and this is not fixation. |
| `mcp-jsonrpc-batch-bypass-001` | Requires the single-request control to be rejected while the batch succeeds. Nothing is rejected, so there is no bypass to demonstrate. |
| `mcp-oauth-dcr-001`, `mcp-oauth-audience-002`, `mcp-oauth-metadata-ssrf-001`, `mcp-confused-deputy-001` | No OAuth registration, authorization, or metadata endpoints exist. |
| `mcp-secret-canary-001` | The canary credential was not echoed in any response. |
| `mcp-sse-resume-replay-001` | Requires two distinct server-minted sessions and id-bearing events to replay. |
| `mcp-header-body-split-001` | The server does not enforce `Mcp-Method` presence, so it is not SEP-2243-aware and there is no split-brain to demonstrate. |

A scanner pointed at a completely open server is under maximum pressure to
over-report. That eleven rules declined, each for a specific documented reason,
is the strongest available evidence that the `confirmed` tier means what it
claims.

### Cross-protocol check

All 17 A2A rules produced **zero findings** against an MCP server: 8 reported
inconclusive (no reachable A2A endpoint) and 9 skipped cleanly on unmet
preconditions. Protocol misidentification does not generate noise.

---

## A2A: `a2a-python` reference sample

The reference A2A agent maintained by the A2A project (`a2a-sdk`).

This target drove the endpoint-discovery work described above. Before that fix,
**every A2A JSON-RPC rule silently missed everything** on this server: the sample
advertises its JSON-RPC interface at `/a2a/jsonrpc` in the agent card, while the
executors POSTed to the target root, received 404, and the scan reported the
target as clean. Because a 404 was indistinguishable from "nothing found", the
failure was invisible.

After [#79](https://github.com/calbebop/batesian/pull/79)–[#81](https://github.com/calbebop/batesian/pull/81),
a re-run resolved the endpoint from the card, issued 16 JSON-RPC requests to
`/a2a/jsonrpc`, and surfaced a genuine `a2a-session-smuggle-001` finding. That
sequence is independently reviewable in the three linked pull requests.

The same run also demonstrated a correct **absence** of a finding:
`a2a-task-cancel-idor-001` reported nothing, because the sample completes tasks
almost immediately and the probe task reached a terminal state before it could be
cancelled. That limitation is documented in the rule catalog rather than papered
over.

> **Reproducing this one is currently awkward.** The `a2a-python` repository has
> restructured and its `samples/` directory no longer carries a runnable agent, so
> the A2A results above date from the pull requests that fixed them rather than
> from a re-run. The MCP results in this document were captured fresh.

---

## Self-validation: fuzzing

Beyond third-party servers, the response parsers are fuzzed, since a scanned host
controls every byte reaching them. Go native fuzz targets cover agent-card
decoding, service-URL selection, task and context id extraction, MCP capability
detection, and the dispatch classifiers that decide whether a `confirmed` finding
is reported ([#90](https://github.com/calbebop/batesian/pull/90)).

Fuzzing found a defect that the unit harnesses could not: evidence truncation
sliced at a byte offset, splitting multi-byte UTF-8 characters. Evidence flows
into JSON and SARIF output, where a trailing partial rune is silently rewritten
to `U+FFFD`, corrupting the reported evidence for any target returning non-ASCII
text. Truncation now backs up to a rune boundary, and the input that found it is
retained as a regression seed.

---

## Reproducing

```sh
# MCP reference server
PORT=3120 npx -y @modelcontextprotocol/server-everything streamableHttp
batesian scan --target http://127.0.0.1:3120 --timeout 20

# Bundled vulnerable fixtures (see testdata/README.md for the registry)
python testdata/mcp_logging_unauth_server.py
batesian scan --target http://127.0.0.1:7797 --rule-ids mcp-logging-unauth-001 -v
```

Reference servers are third-party software; their behavior changes between
versions. The version scanned is recorded above so a differing result can be
attributed to the target rather than to Batesian.
