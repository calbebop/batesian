# MCP Attack Rules

Batesian ships **23 rules** targeting the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).
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

A skip names the reason where the handshake explained itself, because the actions
they call for differ. The common one is a server that requires a credential: it
answers every request and refuses the handshake, so the skip says so rather than
reporting a plainly reachable target as unreachable. It also distinguishes a
refused **anonymous** handshake from a **rejected credential**, since telling an
operator to pass `--token` when they already did is worse than saying nothing, and
several of these rules send no credential by design so that `--token` would change
nothing. An endpoint that answers but does not implement `initialize` is reported
as not speaking MCP. `could not reach a testable endpoint` means what it says:
nothing answered, or no candidate path is served.

## OAuth-gated rules

`mcp-oauth-dcr-001`, `mcp-oauth-audience-002`, `mcp-token-replay-001`,
`mcp-oauth-metadata-ssrf-001` and `mcp-confused-deputy-001` need an OAuth surface
to test: an authorization-server or protected-resource document, or a registration
endpoint. When none is advertised they report **clean**, because a server without
OAuth is not applicable rather than insecure.

That holds only for a server that answered. A target where nothing responded to an
MCP handshake is reported as **not tested**, since a clean result there would say
the OAuth handling is sound about a host the rule never reached. Reachability is
settled with a single `initialize` per candidate, on the bail path only, and a
2026-07-28 server is reported as speaking an unsupported protocol version rather
than as unreachable.

### Client registrations are cleaned up

Three of them register an OAuth client, because what DCR accepts cannot be tested
without asking it to accept something: `mcp-confused-deputy-001` registers one whose
`redirect_uri` points off-origin, `mcp-oauth-dcr-001` one requesting privileged
scopes, and `mcp-oauth-metadata-ssrf-001` one whose metadata URLs point at the scan's
OOB listener. All three delete the client afterwards via RFC 7592 client management,
authenticated with the `registration_access_token` the server itself issued.

Cleanup is best effort and never changes a verdict. A server that returns no
`registration_client_uri`, no `registration_access_token`, or refuses the delete keeps
the client, and the finding's evidence says so and names it: every client is prefixed
`batesian-`, so leftovers are findable. A `registration_client_uri` on a different
host is reported rather than followed, for the same reason the operator's token is
never sent off-host.

The SSRF rule deletes only after its OOB wait, because there the registration *is* the
payload and removing the client first could cancel the fetch being listened for.

## Both protocol wires

A server built on the current SDKs answers **both** the handshake-based revisions
and 2026-07-28 on the same endpoint. The four unauthenticated-access rules,
`mcp-resources-unauth-001`, `mcp-tools-unauth-001`, `mcp-prompt-unauth-001` and
`mcp-completion-unauth-001`, are exercised on each wire it serves, because the two
need not be gated alike: a server can enforce authorization on one and not the
other.

Three of those four read the advertised capability per wire, so a surface the server
exposes on only one era is probed only there: they follow the listing with a
state-touching call (`tools/call`, `prompts/get`, `completion/complete`) and gating
avoids calling a surface the server does not implement.
`mcp-resources-unauth-001` deliberately does not gate, on either wire. A non-empty
`resources/list` answered without a credential is direct evidence of the disclosure,
and what a server advertised is not evidence about what it serves, so gating would
drop the case of a wire listing resources it never declared.

`mcp-dns-rebind-origin-001` is exercised on each wire for the same reason, with the
request each one speaks. Origin validation is normally middleware, so a server can
serve the two wires through different handlers and fix only one.

Findings from the 2026-07-28 wire carry a `[MCP 2026-07-28 wire]` suffix and name
the wire in their evidence, so a surface exposed on both produces two
distinguishable results rather than what looks like a duplicate. A legacy-only
target reports exactly what it reported before, with no suffix.

A modern request carries no session: the protocol version and client capabilities
travel in `params._meta`, the method is mirrored into `Mcp-Method`, and for
`tools/call`, `prompts/get` and `resources/read` the named subject is mirrored into
`Mcp-Name`. Every one of those is mandatory, and a mismatch or omission earns
`-32020`.

`mcp-log-optin-001` runs on the 2026-07-28 wire **only**, because the requirement
it tests was introduced by that revision and has no equivalent on an earlier one.
Against a target serving no such wire it reports itself not applicable rather than
clean.

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
| `mcp-token-replay-001` | [OAuth Token Signature and Audience Validation Bypass](#mcp-token-replay-001) | High / Critical | confirmed | CWE-294 |
| `mcp-resources-unauth-001` | [Unauthenticated Resource Read](#mcp-resources-unauth-001) | High / Critical | confirmed | CWE-862 |
| `mcp-prompt-unauth-001` | [Prompt Templates Without Authentication](#mcp-prompt-unauth-001) | High / Medium | confirmed | CWE-862 |
| `mcp-tools-unauth-001` | [Tools Accessible Without Authentication](#mcp-tools-unauth-001) | High / Medium | confirmed | CWE-862 |
| `mcp-completion-unauth-001` | [completion/complete Without Authentication](#mcp-completion-unauth-001) | High / Medium | confirmed | CWE-862 |
| `mcp-logging-unauth-001` | [logging/setLevel Without Authentication](#mcp-logging-unauth-001) | Medium | confirmed | CWE-862 |
| `mcp-task-idor-001` | [Task Readable Across Authorization Contexts](#mcp-task-idor-001) | Critical / High | confirmed | CWE-639 / CWE-200 |
| `mcp-init-downgrade-001` | [Protocol Version Downgrade Auth Bypass](#mcp-init-downgrade-001) | Critical | confirmed | CWE-757 |
| `mcp-era-downgrade-001` | [Protocol Era Downgrade Auth Bypass](#mcp-era-downgrade-001) | Critical | confirmed | CWE-757 |
| `mcp-session-fixation-001` | [Session ID Fixation](#mcp-session-fixation-001) | High | confirmed | CWE-384 |
| `mcp-header-body-split-001` | [Header/Body Routing Split-Brain (SEP-2243)](#mcp-header-body-split-001) | High | confirmed | CWE-444 |
| `mcp-sse-resume-replay-001` | [SSE Resumption Cross-Session Replay](#mcp-sse-resume-replay-001) | High | confirmed | CWE-488 |
| `mcp-oauth-metadata-ssrf-001` | [OAuth Discovery / Metadata-Fetch SSRF](#mcp-oauth-metadata-ssrf-001) | High | confirmed / indicator | CWE-918 |
| `mcp-secret-canary-001` | [Credential Canary Reflected in Responses](#mcp-secret-canary-001) | Medium | confirmed | CWE-522 |
| `mcp-confused-deputy-001` | [OAuth Confused Deputy via redirect_uri](#mcp-confused-deputy-001) | High / Medium | confirmed / indicator | CWE-441 |
| `mcp-dns-rebind-origin-001` | [Origin Validation / DNS Rebinding](#mcp-dns-rebind-origin-001) | High | confirmed | CWE-350 |
| `mcp-jsonrpc-batch-bypass-001` | [JSON-RPC Batch Authentication Bypass](#mcp-jsonrpc-batch-bypass-001) | High | confirmed | CWE-288 |
| `mcp-session-as-credential-001` | [Session ID Accepted as a Credential](#mcp-session-as-credential-001) | High | confirmed | CWE-287 / CWE-565 |
| `mcp-log-optin-001` | [Log Notifications Without a Per-Request Opt-In](#mcp-log-optin-001) | Medium | confirmed | CWE-200 / CWE-532 |
| `mcp-tool-param-traversal-001` | [Tool Path Traversal](#mcp-tool-param-traversal-001) | High | confirmed | CWE-22 |
| `mcp-scope-confusion-001` | [Tool Scope Confusion](#mcp-scope-confusion-001) | High | confirmed | CWE-285 |

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

Every probe is derived from that expected value, and RFC 7519 section 4.1.3
compares the `aud` claim exactly, so a `--audience-claim` that does not byte-match
what the server uses makes all four probes plain mismatches: the server refuses
them whether or not its matching logic is sound. Before reporting clean on an
operator-supplied value, the rule therefore checks it against the audience the
server advertises and reports **not tested** when the two disagree, naming both.
A finding is never withheld for a disagreement. Hostname case is the likeliest way
to hit this, since DNS is case-insensitive and audience comparison is not.

It submits a **negative control** plus three trap probes as forged HS256 JWTs:

- `aud-control-unrelated` - isolates the audience logic from blanket signature
  failures.
- `aud-substring-trap` - catches `Contains` / `HasPrefix` / `HasSuffix` matchers.
- `aud-case-canonicalization-trap` - catches lowercase/URL-canonicalizing matchers.
- `aud-array-canary-only` - catches validators that skip the array-shape branch.

Every probe rides an MCP `initialize` request, and plenty of servers leave
`initialize` ungated and authorize the calls that follow - a probe accepted
there was accepted by a method that never looked at it. When any probe is
accepted, an anonymous `initialize` control establishes where the gate sits: if
`initialize` itself refuses the anonymous caller, its verdicts stand; if it
answers anyone, every probe is re-judged at the server's first advertised
listing (`ping` when nothing is listable), confirmed to refuse an anonymous
caller, and the evidence names that method. A server that answers both
anonymously is reported **not tested** - the unauthenticated-access rules own
that surface.

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

**OAuth Token Signature and Audience Validation Bypass** | Severity: High / Critical | CWE-294

Submits forged bearer tokens the server cannot have validated: two HS256 tokens
signed with a random key (one with no `aud`, one with a wrong `aud`) and one
unsigned (`alg: none`). A compliant OAuth 2.1 resource server verifies the token
signature and the `aud` claim (RFC 9068, RFC 8707) and rejects all three.
Acceptance is judged at the protocol layer - HTTP 200 + a JSON-RPC `result` - so a
200 carrying an `invalid_token` JSON-RPC error is correctly treated as a rejection.

Before a **confirmed** finding is reported, an anonymous `initialize` control
establishes where the server actually examines tokens: plenty of servers leave
`initialize` ungated and authorize the calls that follow, and an acceptance by a
method that never looked at the token says nothing about validation. If
`initialize` itself refuses the anonymous caller, acceptance there is the
finding. If it answers anyone, the probes are re-run against the server's first
advertised listing (`ping` when nothing is listable), confirmed to refuse an
anonymous caller; only acceptance at that method is a finding. A server that
answers both anonymously is reported **not tested** - the unauthenticated-access
rules own that surface. A confirmed finding therefore means a forged or unsigned
token was accepted on a surface that gates: signature validation is absent,
which also defeats audience binding and enables replay.
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

**Prompt Templates Without Authentication** | Severity: High / Medium | CWE-862

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

The rule needs **two distinct credentials**, because that requirement binds tasks
to an *authorization context* and crossing it needs two of them. Pass two
`--principal` flags (or a config with two principals); with fewer, or with two
principals presenting the same credential, it reports **not tested** rather than
clean. Two identities differing only by a gateway-resolved header are two
contexts, and those headers are sent. Session ids are **not** authorization
contexts, so the rule does not compare them: a server that binds tasks to the
credential but not additionally to the session is conformant, and requiring the
two session ids to differ also made the rule a silent no-op against every
stateless deployment, which mints none.

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

Every precondition reports **not tested** rather than clean when it produced no
verdict: a `tools/list` this principal cannot read, a task creation that was
refused or errored, an anonymous control that returned no answer, and a
cross-context read that never landed. Only a listing that was read and contained
no safely-annotated tool is a genuine not-applicable.

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

### mcp-era-downgrade-001

**Protocol Era Downgrade Auth Bypass** | Severity: Critical | CWE-757

The sibling of `mcp-init-downgrade-001`, with wires in place of versions. The
2026-07-28 revision is a second, independent request path: no handshake, no
session, the protocol version and client capabilities carried in each request's
`_meta`. Servers built on the current Tier-1 SDKs serve it alongside the
handshake revisions at the same URL by default, so an authorization check added to
one request path leaves the other reachable and a caller asks on the wire that
answers.

Serving both eras is spec-compliant and is **not** reported. The finding is the
asymmetry, confirmed by asking the same read-only listing on each wire with no
credentials:

- one wire **refused**, the other **answered** => **confirmed** bypass. Direction
  is irrelevant: whichever wire is open is the one that gets used.
- both answered => the server gates nothing, which is `mcp-resources-unauth-001`
  and `mcp-tools-unauth-001` territory, so this is suppressed rather than
  double-counted.
- both refused => the gate is applied uniformly (secure).
- only one era served => nothing to compare (not applicable).

The listing method is chosen per wire from that wire's **own** advertised
capabilities, since the two need not match: on a server built on the Python SDK
the handshake reports `experimental, prompts, resources, tools` while
`server/discover` reports `prompts, resources, tools`. Comparing a method one wire
does not implement would measure the capability difference rather than the gate.

**Scope.** This compares access at the method level on wires that both open
unauthenticated. A server that gates the handshake itself, so only one wire opens
at all, is not reported here. And no reference implementation currently exhibits
the bug: the SDKs serve both eras correctly and apply no authorization, so the rule
is validated against `testdata/mcp_era_downgrade_server.py` rather than against
one of them.

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
error `-32020` (`HeaderMismatch`). This rule confirms a "policy on headers, execute on body"
split-brain with a participation discriminator (so it never flags servers that
simply don't implement SEP-2243), all with body `method = tools/list`:

1. Omit `Mcp-Method`. If `tools/list` still executes, the server does not enforce
   header presence (not SEP-2243-aware) - no finding.
2. `Mcp-Method: tools/list` (matching) must execute (sanity).
3. `Mcp-Method: tools/call` (mismatched). A **confirmed** finding is raised only
   when the server still executes the body's `tools/list` instead of rejecting -
   it enforces header *presence* but not header/body *consistency*, so a gateway
   that routes or rate-limits on `Mcp-Method` can be bypassed.

**Currency.** SEP-2243 arrived in **2026-07-28**, so the check is driven on every
wire a server serves and is only meaningful on that one. A server whose modern wire
enforces presence is tested on its merits there, and a legacy wire that ignores the
header contributes nothing.

**Not tested** is reported only when no wire exercised the check and the reason was
the revision: a legacy-only server has no such requirement to violate, and calling
that clean would assert header/body consistency about a server never asked. A
server that enforces header presence is tested whatever version it advertises, and
one on 2026-07-28 or later that ignores the header reports clean, since this rule's
subject is the mismatch rather than the absence.

**Two more dimensions of the same requirement.** `Mcp-Name` is a second REQUIRED
header, sourced from `params.name` or `params.uri` on `tools/call`, `resources/read`
and `prompts/get`, carrying the same MUST and the same `-32020`. A server can validate
`Mcp-Method` and ignore it, and this is the higher-impact instance: an intermediary
blocklisting a dangerous **tool or resource** inspects the name, not the method. It is
probed as its own dimension, with the same precondition logic (omission establishes
whether presence is enforced; it is not itself reported, for consistency with the
`Mcp-Method` path).

The subject asked for deliberately does not exist, which keeps that dimension
**read-only**: the oracle is which error comes back, and a server that does not
validate the header is precisely one that would otherwise act on the body. `tools/call`
is never used for it, because probing there would invite a non-validating server to
execute a tool. `Mcp-Param-{Name}` carries the same requirement and is deliberately not
probed at all, for the same reason: those headers come from `x-mcp-header` annotations
on a specific tool's schema, so testing one means calling that real annotated tool.

A fourth probe runs only when the plain mismatch was correctly rejected: header names
are case-insensitive but **values are not**, so `Mcp-Method: TOOLS/LIST` against a body
of `tools/list` must also be refused. A server that executes it validates the value but
folds case, and an exact-match intermediary is walked past.

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
to prevent DNS rebinding. The rule opens each wire the server serves, which is a
request with no Origin that the server accepted, then repeats that exact request
with a foreign Origin (`https://dns-rebind.batesian.invalid`, a non-resolving RFC
6761 host no server should allowlist). The pair differs in the Origin header and
nothing else, and is credential-symmetric, so a refusal cannot be about a missing
token. A **confirmed** finding is raised when the server still returns a JSON-RPC
result for the foreign-Origin request instead of rejecting it with 403.
DNS-rebinding exploitation additionally requires the server to be reachable from a
victim's browser (a local or same-network bind), which the operator confirms for
the deployment; this is the class behind the MCP Inspector RCE (CVE-2025-49596). A
server that answers the foreign Origin with 403 produces no finding, and a probe
that never got an answer is reported as not tested rather than clean.

Requiring a completed handshake, rather than any HTTP 200 carrying a JSON-RPC
result, is load-bearing. An A2A agent answers any method with a Task result, so
scanning one used to produce this finding against a server that speaks no MCP.

**Currency.** The requirement is byte-identical in `2026-07-28`, where it moved to
the transports/streamable-http page. It is stated for "all incoming connections",
is not scoped to a method, and is not conditioned on the server being local; only
the bind-to-localhost SHOULD beside it is. So **both wires are probed**, with the
request each one speaks: `initialize` on the handshake wires, `server/discover` on
2026-07-28, which every server MUST implement. The two are reported separately,
because Origin checking is normally middleware and a server can serve the wires
through different handlers, so a server that has fixed one and not the other reads
as clean if only the fixed one is probed.

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

---

### mcp-session-as-credential-001

**MCP Session ID Accepted as a Credential** | Severity: High | CWE-287 / CWE-565

Tests whether a server treats its own `Mcp-Session-Id` as proof of identity. The
Security Best Practices are explicit: "MCP servers that implement authorization
MUST verify all inbound requests. MCP Servers MUST NOT use sessions for
authentication." A server that authenticates by session has turned a header into
a bearer token, and one that is not scoped, rotated or revocable the way a token
is, travels in plaintext on every request, and is logged by every proxy in the
path. Anyone who reads one out of a log replays the authenticated session, which
is the specification's own Session Hijack Impersonation flow.

The rule needs one working credential (`--token` or a principal), because it asks
whether a session id can stand in for one, which cannot be asked without a
credential to compare against. Without one it reports **inconclusive**, not clean.

1. Handshake **with** the credential and capture the server-minted session id. No
   session id means the server is stateless and the rule does not apply.
2. `tools/list` with the session id **and** the credential must succeed, or the
   session is not usable and there is nothing to strip.
3. Control: attempt an **anonymous** handshake, and if it yields a session, call
   `tools/list` with that session and no credential. A server that answers it has
   served a caller who never presented a credential, so it implements no
   authorization, the requirement above does not bind on it, and the surface
   belongs to `mcp-tools-unauth-001`. An open handshake alone proves nothing: many
   servers leave `initialize` ungated and authorize what follows. If the anonymous
   handshake is accepted but issues no session, the rule stops, since a refusal
   below could then be about the missing session rather than the missing credential.
4. Control: `tools/list` with **no session and no credential**. A server that
   answers it is open on this surface, so a later success cannot be attributed to
   the session id.
5. Control: `tools/list` presenting a **random, never-issued** session id and no
   credential. A server that accepts this treats the presence of the header as
   authorization, so the issued id is not what decided it.
6. `tools/list` presenting the **real** session id and no credential.

A **confirmed** finding is raised only when step 6 is answered. Steps 5 and 6 are
the same request differing in one detail, so the session id is provably the
deciding factor rather than an inference. When step 3 produced an anonymous
session, steps 3 and 6 form a second and stronger such pair: both ids were minted
by this server, and the only difference is whether a credential was presented when
they were opened. Step 3 is what separates a server that
authenticates by session from one that merely requires a session and authenticates
nothing: both refuse steps 4 and 5, for different reasons. The official C# SDK's
stateful sample is the second kind, and was reported as vulnerable until that
control was added.

Currency: `Mcp-Session-Id` is normative in revisions 2025-03-26 through
2025-11-25. The 2026-07-28 revision removes protocol-level sessions, so a server
on that revision returns no session id and the rule reports itself not applicable
at step 1.

---

### mcp-log-optin-001

**MCP Server Emits Log Notifications Without a Per-Request Opt-In** | Severity:
Medium | CWE-200 / CWE-532

Tests whether a server sends log notifications to a request that never asked for
them. `2026-07-28` removed `logging/setLevel` and replaced it with a per-request
opt-in, and the logging page is explicit: "To receive log messages for a specific
request, include `io.modelcontextprotocol/logLevel` in the request's `_meta`. The
server MUST NOT emit `notifications/message` for a request that does not include
this field."

That is the bug the revision created. A server carried over from the `setLevel`
era holds a connection-global level and emits unconditionally, so a client that
never opted in receives server-side log content. The same page requires that log
messages carry no credentials, personal data or internal system details, which is
an acknowledgement of what they usually do carry, and an MCP client feeds what the
server sends into a model's context.

Emitting logs is a MAY, so **absence proves nothing**: a server that never logs is
indistinguishable from one that respects the gate. Two probes, in this order:

1. Control: `tools/list` **with** `io.modelcontextprotocol/logLevel` = `debug` in
   `_meta`. At least one `notifications/message` frame must come back, otherwise
   the server does not log on this surface and the probe below could not tell
   compliance from silence. The rule then reports **not tested**, never clean.
2. Probe: the identical `tools/list` with **no** `logLevel` in `_meta`. Any
   `notifications/message` frame is the finding.

Only positive evidence is reported. A server that stays silent for the control is
left alone; a server that logs for the control and not for the probe is a genuine
clean result, because it demonstrably logs here and withheld the frames when they
were not requested. The probe is a read: `tools/list` creates nothing, calls no
tool and modifies no state. The evidence also records whether the server declares
the `logging` capability, which it MUST when it emits log notifications, so one
that emits them unasked and undeclared is breaking two requirements.

The frames are only visible on the raw stream, so this rule reads the SSE stream
itself rather than through the shared client, which collapses a stream to its
JSON-RPC response event and would discard exactly the frames being looked for.

**Currency.** The field and its MUST NOT exist only in `2026-07-28`, so the rule
runs on that wire alone and reports itself not applicable against a target serving
no such wire. The Logging feature as a whole is also deprecated as of the same
revision (SEP-2577): it stays in the specification for at least twelve months and
is eligible for removal in the first revision released on or after `2027-07-28`,
with new implementations told to log to stderr or use OpenTelemetry instead. The
requirement is normative until then, and the servers most likely to break it are
the ones migrating off `logging/setLevel`.

---

### mcp-tool-param-traversal-001

**Tool Path Traversal (Unvalidated Filesystem Arguments)** | Severity: High | CWE-22

Probes whether read-only MCP tools validate filesystem-style path arguments
against escaping their intended root. A tool that joins a caller-supplied path
onto an internal directory without checking where the join lands lets `../..`
walk out of that directory and read any file the server process can access.
This is the defect class behind CVE-2025-53109 (Filesystem EscapeRoute) and
CVE-2026-27825 (mcp-atlassian), and it lives in ordinary tool arguments rather
than in the transport or authorization layer the other rules here cover.

**Safety.** This rule invokes real tools by name, which only
`mcp-task-idor-001` also does, so it inherits that rule's gate and tightens it:

1. Only tools whose annotations declare `readOnlyHint: true`, or explicitly
   `destructiveHint: false`, are dispatched. An unannotated tool is never
   touched, even one the scanner believes is vulnerable - the fixture keeps an
   unannotated broken tool precisely to pin this.
2. Every probe reads a file that does not exist: a per-run canary name. No file
   content is ever returned and nothing on the target changes.

**Oracle.** Servers that resolve the joined path before opening it usually say
where they looked when it is not there; a Node ENOENT names the resolved
absolute path. Three requests go to each candidate parameter: a no-traversal
baseline naming only the canary, an absolute path carrying a dot-dot chain, and
a backslash variant for Windows-style joins. The finding fires only when a
traversal probe discloses a **resolved** absolute lookup in a directory outside
the baseline's own tree - the server's own resolution proves the escape with
zero bytes read. An echo of the caller's input with its dot-dot segments intact
is not resolution evidence and is ignored, so a chatty read-only tool is not
accused of traversal for repeating what it was sent. Without a baseline
resolution to compare against, the rule declines to report rather than guess
containment from a single lookup.

Candidates are annotated-safe tools exposing a string parameter named like a
filesystem path (`path`, `file_path`, `filename`, `directory`, ...). A server
whose safe tools take no such parameter reports clean: the rule does not
dispatch unannotated tools, and the catalog records that trade-off here rather
than hiding it behind a clean-looking result.

---

### mcp-scope-confusion-001

**Tool Scope Confusion (Valid Token, Privileged Dispatch)** | Severity: High | CWE-285

Tests whether `tools/call` enforces the scopes of the credential presented, or
merely that a credential exists. The failure sits between two rules that
already ship: `mcp-token-replay-001` covers tokens the server cannot have
validated, and `mcp-oauth-dcr-001` covers registration granting privileged
scopes. Neither says anything about a validly-signed, genuinely-issued token
whose scope set is too small. Servers that authenticate correctly and then
authorize nothing per-tool hand every authenticated caller every tool - OWASP
MCP02 scope creep.

**Two identities drive it**, via the same `--principal` machinery the
cross-principal rules use: principal A holds full privilege, principal B a
deliberately limited one. For each privileged-looking candidate tool -
annotations declaring it non-read-only or destructive, or write/admin
vocabulary in its name - the rule sends the SAME invalid-subject call twice:

1. As principal A. The baseline must reach argument validation; a
   `-32602`-style answer proves the dispatcher ran for a legitimate caller
   and that the call shape is not what gets refused.
2. As principal B. An authorization refusal here is the boundary holding,
   which is the pass sought. Dispatching like A while an unauthenticated
   control was refused means the server authenticates callers and then
   ignores what their credential is scoped to do - reported **confirmed**
   at high.

**Safety.** The arguments are invalid on purpose: every required string
parameter names an object that does not exist. A scope-ignoring server stops
at argument validation and executes nothing; the oracle never needs a
successful state-changing call, which is the same never-executes trick
`mcp-tools-unauth-001` uses on its dispatch probe.

**Controls.** The limited credential must succeed somewhere (`tools/list`)
before any refusal below is read as a scope decision rather than a dead
token. An anonymous call on the first candidate must be refused: a server
that dispatches unauthenticated calls gates nothing by identity, which
belongs to `mcp-tools-unauth-001`, and reporting it as a scope failure would
count one defect twice under the wrong name.

**Precondition.** Two distinct credentials are required, because crossing a
scope boundary needs two differently-scoped ones. With fewer - or with two
principals presenting the same credential - the rule reports **not tested**
rather than clean, naming what was missing.
