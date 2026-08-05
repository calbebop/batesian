# MCP Attack Rules

Batesian ships **18 rules** targeting the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).
Every rule is an active probe: it sends crafted protocol traffic and judges the
server's actual response. Rules are deliberately scoped to MCP-specific semantics
(OAuth 2.1 authorization, DCR, audience binding, discovery-chain metadata-fetch
SSRF, protocol-version negotiation, tools/prompts/resources access control,
session-id handling, SEP-2243 Streamable HTTP header/body routing, SSE resumption,
credential leakage into responses) rather than generic web hygiene.

Each finding carries a **confidence**:

- **confirmed** - the attack was demonstrably successful (e.g. data returned
  without a token, a forged token accepted against a rejecting baseline, a
  privileged scope granted to an anonymous client).
- **indicator** - a suspicious posture was observed but exploitation could not be
  proven from the response alone; manual verification is recommended.

Acceptance is judged at the **protocol layer** throughout: a probe counts as
accepted only on HTTP 200 carrying a JSON-RPC `result` envelope. A 200 with a
JSON-RPC `error` (the common MCP rejection shape) is a rejection, not a finding.

## Protocol currency

These rules target the **handshake-based** MCP revisions (`2024-11-05` through
`2025-11-25`), which establish a session with `initialize` and carry
`Mcp-Session-Id`.

The **`2026-07-28`** revision makes MCP stateless. It removes the
`initialize`/`notifications/initialized` handshake in favour of per-request
`_meta`, removes protocol-level sessions and the `Mcp-Session-Id` header,
removes the HTTP GET stream and `Last-Event-ID` resumability, removes
`logging/setLevel`, and moves tasks into an extension. Individual rules whose
surface changed carry a **Currency** note below.

The Tier-1 SDKs shipped that revision on 2026-07-27 and 2026-07-28: TypeScript
`@modelcontextprotocol/server` 2.0.0, Python `mcp` 2.0.0, Go 1.7.0, C# 2.0.
**They serve both eras from one server.** A 2026-era server built on the Python
or TypeScript SDK answers `server/discover` *and* the 2025-era `initialize`
handshake on the same endpoint, unless the deployment goes out of its way to
disable the older one. These rules therefore keep working against current
servers, and era detection only reports a target as unsupported when it is
modern-only.

`@modelcontextprotocol/server-everything`, the example server, is a separate
matter: it is still pinned to the 1.x SDK and negotiates `2025-11-25`. Its
version is not a signal about the ecosystem.

Era detection itself is checked weekly against a server built on the current
official SDK (`.github/workflows/mcp-era-watch.yml`, using
`testdata/mcp_modern_era_server.py`), so a change in the specification, the SDK,
or our classification surfaces as a failing job rather than as a wrong scan
result.

Rules gate on advertised capabilities and on reaching a live endpoint, so
against a server this rule set cannot handshake with they report **inconclusive
or skip**, never a clean pass. A target that could not be exercised is reported
as not tested rather than as secure.

## Endpoint discovery

A target that names a path is probed as given; otherwise `/mcp`, `/`, `/api` and
`/rpc` are tried in that order. The walk **stops at the first path that answers as
an MCP endpoint**, because the remaining candidates are the same server at paths
it does not serve, so probing them yields 404s rather than coverage. Only when no
candidate answers does a rule report that it could not test.

| Rule ID | Attack | Severity | Confidence | CWE |
|---|---|:---:|:---:|---|
| `mcp-oauth-dcr-001` | [OAuth DCR Scope Escalation](#mcp-oauth-dcr-001) | High | indicator | CWE-284 |
| `mcp-oauth-audience-002` | [OAuth Audience Matching Bug Probes](#mcp-oauth-audience-002) | High | confirmed / indicator | CWE-863 |
| `mcp-token-replay-001` | [OAuth Token Signature and Audience Validation Bypass](#mcp-token-replay-001) | High | confirmed | CWE-294 |
| `mcp-resources-unauth-001` | [Unauthenticated Resource Read](#mcp-resources-unauth-001) | High / Critical | confirmed | CWE-862 |
| `mcp-prompt-unauth-001` | [Prompt Templates Without Authentication](#mcp-prompt-unauth-001) | Medium | confirmed | CWE-862 |
| `mcp-tools-unauth-001` | [Tools Accessible Without Authentication](#mcp-tools-unauth-001) | High / Medium | confirmed | CWE-862 |
| `mcp-completion-unauth-001` | [completion/complete Without Authentication](#mcp-completion-unauth-001) | High / Medium | confirmed | CWE-862 |
| `mcp-logging-unauth-001` | [logging/setLevel Without Authentication](#mcp-logging-unauth-001) | Medium | confirmed | CWE-862 |
| `mcp-task-idor-001` | [Task Readable Across Authorization Contexts](#mcp-task-idor-001) | Critical / High | confirmed | CWE-639 / CWE-200 |
| `mcp-init-downgrade-001` | [Protocol Version Downgrade Auth Bypass](#mcp-init-downgrade-001) | Critical | confirmed | CWE-757 |
| `mcp-session-fixation-001` | [Session ID Fixation](#mcp-session-fixation-001) | High | confirmed | CWE-384 |
| `mcp-header-body-split-001` | [Header/Body Routing Split-Brain (SEP-2243)](#mcp-header-body-split-001) | High | confirmed | CWE-444 |
| `mcp-sse-resume-replay-001` | [SSE Resumption Cross-Session Replay](#mcp-sse-resume-replay-001) | High | confirmed | CWE-488 |
| `mcp-oauth-metadata-ssrf-001` | [OAuth Discovery / Metadata-Fetch SSRF](#mcp-oauth-metadata-ssrf-001) | High | confirmed / indicator | CWE-918 |
| `mcp-secret-canary-001` | [Credential Canary Reflected in Responses](#mcp-secret-canary-001) | Medium | confirmed | CWE-522 |
| `mcp-confused-deputy-001` | [OAuth Confused Deputy via redirect_uri](#mcp-confused-deputy-001) | High / Medium | confirmed / indicator | CWE-441 |
| `mcp-dns-rebind-origin-001` | [Origin Validation / DNS Rebinding](#mcp-dns-rebind-origin-001) | High | confirmed | CWE-350 |
| `mcp-jsonrpc-batch-bypass-001` | [JSON-RPC Batch Authentication Bypass](#mcp-jsonrpc-batch-bypass-001) | High | confirmed | CWE-288 |

---

## Rule Details

### mcp-oauth-dcr-001

**OAuth Dynamic Client Registration Scope Escalation** | Severity: High | CWE-284

Sends a single **unauthenticated** dynamic client registration (DCR) requesting
admin/write scopes, then inspects the *granted* scope set. Open/anonymous DCR is
permitted by RFC 7591 and supported by the MCP spec, so it is **not** flagged on
its own - and neither is redirect-URI shape (loopback redirects are endorsed by
RFC 8252). The rule fires an **indicator** finding only when the granted scopes
still contain a privileged token, compared per whitespace-delimited scope token
(RFC 6749 section 3.3), not by substring. This is registration-time evidence: the
scope policy is permissive, but whether a privileged token is actually issued
depends on the grant/consent step, so manual verification is recommended. A server
that rejects the registration or reduces the grant to read-only produces no finding.

---

### mcp-oauth-audience-002

**OAuth Audience Matching Bug Probes** | Severity: High | CWE-863

Tests whether the server's `aud` matching logic is robust to common
implementation bugs, once the expected audience is known (via `--audience-claim`
or RFC 9728 auto-discovery). Without one, the outcome depends on whether anything
answered: an MCP server that advertises no metadata has no audience to check
against, so that is a **clean** result, while a target where nothing answered the
handshake is reported as **not tested**.
It submits a **negative control** plus three trap probes as forged HS256 JWTs:

- `aud-control-unrelated` - isolates the audience logic from blanket signature
  failures.
- `aud-substring-trap` - catches `Contains` / `HasPrefix` / `HasSuffix` matchers.
- `aud-case-canonicalization-trap` - catches lowercase/URL-canonicalizing matchers.
- `aud-array-canary-only` - catches validators that skip the array-shape branch.

**Honest scope.** Because the probes are forged self-signed HS256 tokens,
acceptance indicates a *compound* failure of signature validation **and** audience
matching. The negative control disambiguates: if the control is accepted, the
server accepts any forged token regardless of audience, so the result is reported
as **blanket forged-token acceptance** (point at `mcp-token-replay-001`) rather
than misattributed to a specific matching bug. A trap acceptance is a
**confirmed** isolated matching bug only when the control was rejected; a
control that carried no JSON-RPC result envelope (so it could not be clearly
rejected) downgrades trap acceptances to an **indicator**, and a 2xx body with
no result envelope is never itself treated as acceptance. Catching a
server that validates signatures correctly but still mishandles `aud` (the
CVE-2026-30863 / RFC 7523-bis class) requires a real validly-signed cross-resource
token and is tracked as a follow-up.

---

### mcp-token-replay-001

**OAuth Token Signature and Audience Validation Bypass** | Severity: High | CWE-294

Submits forged bearer tokens the server cannot have validated: two HS256 tokens
signed with a random key (one with no `aud`, one with a wrong `aud`) and one
unsigned (`alg: none`). A compliant OAuth 2.1 resource server verifies the token
signature and the `aud` claim (RFC 9068, RFC 8707) and rejects all three.
Acceptance is judged at the protocol layer - HTTP 200 + a JSON-RPC `result` - so a
200 carrying an `invalid_token` JSON-RPC error is correctly treated as a rejection.
A **confirmed** finding means a forged or unsigned token was accepted: signature
validation is absent, which also defeats audience binding and enables replay.
Audience-matching bugs on signature-valid tokens are isolated by
`mcp-oauth-audience-002`.

---

### mcp-resources-unauth-001

**Unauthenticated Resource Read** | Severity: High / Critical | CWE-862

Sends `resources/list` and `resources/read` with no credentials. Unlike
LLM-mediated tool issues, resource disclosure is immediate - the attacker
retrieves data directly. All findings are **confirmed** (the data was actually
returned without a token). Severity is **impact-graded**: an unauthenticated list
and a readable resource are **high**; the read is escalated to **critical** only
when the returned content matches a credential pattern (AWS/OpenAI/GitHub keys,
private keys, JWTs, password assignments, `Authorization: Bearer <token>` headers,
credentials in a URI userinfo section such as `postgresql://user:pass@host/db`),
and the matched pattern is cited in the evidence.

Up to five resources are read, stopping at the first one that matches, and the
finding reports that resource. Reading only the first would leave the severity to
the server's list order, so a deployment that lists a public README ahead of its
database credentials would be graded high. The evidence states how many resources
were examined against how many were listed, so a run that stopped at the bound is
distinguishable from one that saw everything.

---

### mcp-prompt-unauth-001

**Prompt Templates Without Authentication** | Severity: Medium | CWE-862

Sends `prompts/list` and `prompts/get` without credentials. Prompt templates can
encode system-level instructions and internal context that were not intended to be
public. The prompts capability is confirmed structurally from the captured
`initialize` result (`ServerSupports`), not by substring-matching the response
body. A list-only disclosure is **medium**; retrieving template content as well is
**high** - both **confirmed**. A server that requires auth, or does not advertise
the prompts capability, produces no finding.

---

### mcp-tools-unauth-001

**Tools Accessible Without Authentication** | Severity: High / Medium | CWE-862

Tools are the primary MCP attack surface: a tool is a server-side function a
caller can invoke, not just data or a template. The tools capability is confirmed
structurally from the captured `initialize` result (`ServerSupports`). The rule
confirms two failures: an unauthenticated `tools/list` discloses the executable
surface and each tool's input schema (**medium**); and the `tools/call` dispatch
path being reachable without auth (**high**) - both **confirmed**. To prove
call-path reachability **without executing anything**, the rule calls a guaranteed
non-existent tool name, which the spec answers with a `-32602` "Unknown tool"
protocol error; reaching that error (or any result envelope) shows the call was
dispatched without credentials. It **never invokes a real or advertised tool** -
destructive tool-argument fuzzing is out of scope. A server that requires auth, or
does not advertise the tools capability, produces no finding.

---

### mcp-completion-unauth-001

**completion/complete Without Authentication** | Severity: High / Medium | CWE-862 / CWE-200

`completion/complete` returns autocompletion suggestions for prompt arguments and
resource-template URIs; servers that support it advertise the `completions`
capability, which is confirmed structurally from the captured `initialize` result
(`ServerSupports`). The MCP spec requires implementations to control access to
completion suggestions and prevent completion-based information disclosure, so an
unauthenticated completion endpoint is both an access-control failure and an
enumeration oracle. The rule confirms two outcomes: `completion/complete`
dispatching an unauthenticated request (**medium**), and returning real suggestion
values for a discovered prompt argument or resource-template variable (**high**) -
both **confirmed**. To establish reachability without depending on an open
prompts/resources listing, the rule falls back to a synthetic prompt reference,
which the spec answers with a `-32602` (invalid params) protocol error; reaching
that error (or any result envelope) shows the call was dispatched without
credentials. The probe is read-only - it never executes a tool and sends only
benign single-character argument values. A server that requires auth, or does not
advertise the completions capability, produces no finding.

---

### mcp-logging-unauth-001

**logging/setLevel Without Authentication** | Severity: Medium | CWE-862

`logging/setLevel` sets the server's minimum log verbosity; servers that support
it advertise the `logging` capability, confirmed structurally from the captured
`initialize` result (`ServerSupports`). The MCP spec's Security section requires
implementations to control log access, so an unauthenticated `logging/setLevel` is
an access-control failure on a state-changing method: an anonymous caller can
flood logs at `debug` (cost/DoS and burying attack traces) or suppress them at
`emergency` (hiding malicious activity). The rule gates on the capability, then
sends one `logging/setLevel` with a deliberately **invalid** level string; a
`-32602` (invalid params) error - or any result envelope - proves the handler was
dispatched without auth, while the invalid level means the server's real verbosity
is never changed. A server that rejects with HTTP 401/403 or an auth error, or
does not advertise the logging capability, produces no finding. Reported
**confirmed** at medium severity.

**Currency.** `logging/setLevel` is normative in revisions 2024-11-05 through
2025-11-25. The **2026-07-28** revision **removes the method outright** (log
level is now set per-request via `io.modelcontextprotocol/logLevel` in `_meta`)
and deprecates the Logging feature as a whole. This rule therefore applies to
servers on the earlier revisions. Because it gates on the advertised `logging`
capability, a 2026-07-28 server is skipped rather than producing a false result.

---

### mcp-task-idor-001

**Task Readable Across Authorization Contexts** | Severity: Critical / High | CWE-639 / CWE-200

MCP 2025-11-25 added durable **tasks**: a task-augmented `tools/call` returns a
`taskId` immediately, and the caller later reads execution state with `tasks/get`
and the underlying tool output with `tasks/result`. The spec's Security
Considerations require that "receivers MUST reject `tasks/get`, `tasks/result`,
and `tasks/cancel` requests for tasks that do not belong to the same
authorization context as the requestor".

The rule creates a task as one principal and reads it from a separate session as
another, reporting three failures, all **confirmed**:

- An accepted cross-context `tasks/get` discloses another context's task
  metadata: status, timing, and status messages (**high**).
- An accepted cross-context `tasks/result` discloses the **actual tool output**
  the task produced, not metadata (**critical**).
- An accepted cross-context `tasks/list` **enumerates** another context's tasks
  (**critical**). This is the strongest of the three because it needs no prior
  knowledge of any task id at all, so every task on the server can be listed and
  then read. It is gated on the `tasks.list` capability being advertised, and is
  checked independently of the by-id failures: the spec requires anything
  gettable to also be listable, but not the converse, so a server can scope
  `tasks/get` and still leak the list.

A finding is raised only after anonymous task creation is *rejected*, proving the
server does enforce authentication. A server with no authentication at all is a
different and more obvious failure owned by `mcp-tools-unauth-001`, and is
suppressed here rather than mislabelled as broken object-level authorization. A
server that scopes tasks to their creating context answers the cross-context read
with `-32602` and produces no finding.

**Safety.** Creating a task requires invoking a real tool, which is unique among
the rules in this package (`mcp-tools-unauth-001` deliberately calls a
non-existent tool so nothing executes). The rule therefore only invokes a
task-capable tool whose annotations declare it `readOnlyHint: true` or
explicitly `destructiveHint: false`, and skips entirely when no such tool is
advertised; an unannotated tool is never invoked, since MCP treats a non-read-only
tool as potentially destructive by default. Because `tasks/result` blocks until a
task is terminal, the rule polls `tasks/get` within a bounded budget and requests
the result only once the task has finished.

**Currency.** Tasks were introduced as experimental in 2025-11-25, and the
**2026-07-28** revision moved them out of the core protocol into the
`io.modelcontextprotocol/tasks` extension: the blocking `tasks/result` is
replaced by polling `tasks/get`, `tasks/update` is added, and **`tasks/list` is
removed**. This rule targets the 2025-11-25 core shape and gates on the core
`tasks` capability, so a 2026-07-28 server advertising the extension instead is
skipped rather than mis-tested. Covering the extension is separate work.

---

### mcp-init-downgrade-001

**Protocol Version Downgrade Auth Bypass** | Severity: Critical | CWE-757

Negotiating an older protocol version (`2024-11-05`, which predates the mandatory
OAuth 2.1 authorization framework) is, by itself, **spec-compliant** and is *not*
a finding. The rule confirms a true downgrade bypass with a discriminator: it
calls `resources/list` under both a modern-version session and a legacy-version
session and compares outcomes. The probe runs **unauthenticated** (it ignores any
`--token`): the bypass is the ability to reach protected functionality without
credentials, so attaching a token would let an auth-enforcing server grant the
modern path and mask the bug. A **confirmed** finding is reported only when the
modern session is rejected (auth enforced) but the legacy session succeeds. If
both succeed, the server simply has no auth (owned by `mcp-resources-unauth-001`);
if both are rejected, the server is secure - neither produces a finding here.

---

### mcp-session-fixation-001

**Session ID Fixation** | Severity: High | CWE-384

A **stateful, chained** rule (the MCP half of the session/task-ID fixation
story). The Streamable HTTP transport requires the server to assign the
`Mcp-Session-Id` at initialize and to reject an unrecognized id with HTTP 404; a
server that instead **adopts a client-chosen id** is vulnerable to session
fixation. The rule confirms the failure with a control to avoid false positives
on servers that track no sessions at all:

0. An ordinary `initialize` establishes that the target is a reachable MCP
   server. Reachability is judged here, and not from the seeded handshake below,
   because a server may reject that handshake outright: the reference
   implementation answers it `400` / `-32000 "Bad Request: No valid session ID
   provided"`. That refusal is the defence this rule tests for, so it is graded
   as a clean pass rather than as an untestable target.
1. `initialize` carrying a client-chosen `Mcp-Session-Id`. If the server rejects
   it, or returns its **own** id instead, the id is not client-controllable and
   no finding is raised.
2. A follow-up call presenting the attacker-chosen id must be **accepted**.
3. Control: the same call presenting a different, **never-initialized** random id
   must be **rejected** (404). If it is also accepted, the server enforces no
   sessions at all (not fixation) and the finding is suppressed.

A **confirmed** finding is raised only when the pre-seeded id is accepted while
the un-initialized id is rejected - proving sessions are enforced yet a
client-supplied identifier was trusted. When two principals are configured, a
fourth provenance hop shows the pre-seeded session being borrowed by a different
principal. The A2A counterpart is `a2a-context-fixation-001`.

---

### mcp-header-body-split-001

**Header/Body Routing Split-Brain (SEP-2243)** | Severity: High | CWE-444

SEP-2243 mirrors the JSON-RPC `method` into an `Mcp-Method` HTTP header so
intermediaries can route/police Streamable HTTP traffic without parsing the body,
and requires servers to reject a header/body mismatch with `400` and JSON-RPC
error `-32001`. This rule confirms a "policy on headers, execute on body"
split-brain with a participation discriminator (so it never flags servers that
simply don't implement SEP-2243), all with body `method = tools/list`:

1. Omit `Mcp-Method`. If `tools/list` still executes, the server does not enforce
   header presence (not SEP-2243-aware) - no finding.
2. `Mcp-Method: tools/list` (matching) must execute (sanity).
3. `Mcp-Method: tools/call` (mismatched). A **confirmed** finding is raised only
   when the server still executes the body's `tools/list` instead of rejecting -
   it enforces header *presence* but not header/body *consistency*, so a gateway
   that routes or rate-limits on `Mcp-Method` can be bypassed.

---

### mcp-sse-resume-replay-001

**SSE Resumption Cross-Session Replay (Last-Event-ID)** | Severity: High | CWE-488

The 2025-03-26 / 2025-06-18 Streamable HTTP transport lets a client resume a
broken SSE stream with a `Last-Event-ID` header; the spec requires that a server
MUST NOT replay another stream's messages. This rule confirms a cross-session
leak only, using two distinct server-minted sessions: (1) initialize session A
and open its SSE stream, capturing a checkpoint event id and an A-specific data
marker (if the server mints no distinct session id or emits no id-bearing event,
the rule can't test - no finding); (2) initialize session B (must differ from A);
(3) as B, resume from before A's checkpoint. A **confirmed** finding is raised
only when B's resumed stream delivers A's exact data marker - the resumption
buffer is not scoped to the originating session. A server that replays only the
requester's own events, or ignores `Last-Event-ID`, produces no finding. (Note:
the 2026-07 draft removes resumability, so this is version-scoped.)

---

### mcp-oauth-metadata-ssrf-001

**OAuth Discovery / Metadata-Fetch SSRF** | Severity: High | CWE-918

RFC 7591 dynamic client registration lets a registrant supply URL-valued metadata
(`jwks_uri`, `sector_identifier_uri`, `logo_uri`, `client_uri`, `policy_uri`,
`tos_uri`). Some authorization servers fetch these server-side at registration to
validate or render them; without an allow-list, a registrant can point them at
internal services or cloud metadata endpoints - SSRF in the OAuth discovery chain.
This complements `mcp-oauth-dcr-001` (scope escalation), which does not test the
fetch surface. The check is **OOB-confirmed**: it discovers the registration
endpoint, sends an unauthenticated registration whose URL fields all point at the
Batesian OOB listener (each with a unique marker path), and raises a **confirmed**
finding only when the listener receives an inbound request - the marker path names
which field was fetched. With an external `--oob-url`, registration acceptance is
reported as an **indicator** for the operator to confirm via their collaborator.

---

### mcp-secret-canary-001

**Credential Canary Reflected in Responses** | Severity: Medium | CWE-522

Presents a unique, high-entropy canary bearer token across a handful of standard
calls (`initialize`, `tools/list`, `resources/list`, and a malformed call to
elicit a verbose error) and checks whether the canary value appears verbatim in
any response body. If it does, the server copies the caller's credential into its
protocol output - a channel that flows into server logs, distributed traces, error
trackers, shared SSE streams, and client consoles, exposing the secret to anyone
with access to those sinks. Reported **confirmed** at medium severity; a server
that rejects or errors without echoing the token produces no finding. The canary
is unique per run, so a substring match cannot false-positive. This is the
black-box-observable half of secret leakage; verifying secrets never reach
external log/trace sinks additionally requires access to those sinks.

---

### mcp-confused-deputy-001

**OAuth Confused Deputy via redirect_uri Validation** | Severity: High / Medium | CWE-441 / CWE-601

An MCP server that proxies OAuth to a third-party authorization server with a
static client_id, while forwarding a client-supplied redirect_uri, is open to a
confused deputy attack: once the upstream consent screen is skipped (a consent
cookie for the static client_id), an attacker who supplies their own redirect_uri
harvests the authorization code. The MCP Security Best Practices require exact
redirect_uri matching and per-client consent, and RFC 6749 Section 4.1.2.1
requires the server to reject a mismatching redirect_uri and not redirect to it.
The check registers a client via DCR with an off-origin redirect, then requests
`/authorize` with a different, unregistered off-origin redirect (both on the
reserved `.invalid` TLD, so they never resolve and no code is ever harvested). A
**confirmed** finding is raised only when the server answers with a 3xx whose
Location host is the unregistered redirect - a direct exact-match violation. If
DCR instead accepted the arbitrary off-origin redirect but the authorize-time
check could not be disproven, an **indicator** is raised for the precondition.
Servers with no DCR endpoint (e.g. 2025-11-25 Client ID Metadata Document
deployments) or no authorization endpoint are out of scope and produce no
finding.

---

### mcp-dns-rebind-origin-001

**Origin Validation / DNS Rebinding** | Severity: High | CWE-350 / CWE-346

The Streamable HTTP transport requires servers to validate the Origin header on
every connection and respond `HTTP 403 Forbidden` to a present, invalid Origin,
to prevent DNS rebinding. The rule first POSTs a normal `initialize` with no
Origin (baseline: it must be accepted, confirming a responsive MCP endpoint),
then POSTs the same `initialize` with a foreign Origin
(`https://dns-rebind.batesian.invalid`, a non-resolving RFC 6761 host no server
should allowlist) - the only difference is the Origin header. A **confirmed**
finding is raised when the server still returns a JSON-RPC result for the
foreign-Origin request instead of rejecting it with 403. DNS-rebinding
exploitation additionally requires the server to be reachable from a victim's
browser (a local or same-network bind), which the operator confirms for the
deployment; this is the class behind the MCP Inspector RCE (CVE-2025-49596). A
server that answers the foreign Origin with 403 produces no finding.

---

### mcp-jsonrpc-batch-bypass-001

**JSON-RPC Batch Authentication Bypass** | Severity: High | CWE-288

Tests whether authentication can be bypassed by wrapping a request in a JSON-RPC
batch array. The classic failure: an auth gate inspects the top-level request
object (for example "allow initialize, require auth for everything else", keyed on
`body.method`); a batch is an array with no top-level method, so the gate does not
fire and the dispatcher runs each element. Detection sends the **identical**
request twice, differing only in batch wrapping: a single object (control) and a
one-element array (test). A **confirmed** finding is raised only when the control
is rejected (HTTP 401/403 or a JSON-RPC auth error) but the batch is processed and
returns a result. Two gate shapes are probed: an auth gate on `initialize`, and a
per-method gate on `tools/resources/prompts` list when `initialize` is open. A
server that rejects the batch the same way, or rejects the array outright,
produces no finding. The rule only sends `initialize` and `*list` requests; it
never invokes a tool or mutates state.

Currency: JSON-RPC batching is normative in revisions 2024-11-05 and 2025-03-26
and was removed in 2025-06-18, so a compliant current server rejects batches. The
rule targets servers on the earlier revisions and any later server that still
processes batches (non-compliant), where the bypass is exploitable.
