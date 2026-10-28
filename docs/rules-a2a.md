# A2A Attack Rules

Batesian ships **21 rules** targeting the [Agent-to-Agent (A2A) protocol](https://a2a-protocol.org/).
Every rule is an active probe: it sends crafted protocol traffic and judges the
server's actual response. Rules are deliberately scoped to A2A-specific semantics
(agent cards, JWS card signatures, tasks/contexts, push notifications, peer
identity) rather than generic web hygiene.

Each finding carries a **confidence**:

- **confirmed** - a tested security boundary failed (for example, a tampered
  value was read back despite a rejecting control).
- **indicator** - access or another risk-relevant posture was observed, but the
  response alone does not establish a policy violation.

An exact `expected_denials` entry can confirm an observed task read, list, or
cancellation when the operator declares that caller/owner relationship forbidden.
It does not promote errors or unverified access.

## Protocol currency

The catalog covers selected **A2A v1.0** operations, including the v1.0.1
patch. Task rules generally try PascalCase methods with `A2A-Version: 1.0`
before v0.3 slash methods, and card rules read both v1.0
`securityRequirements` and v0.3 `security`. Binding support and fallbacks vary
by rule; the entries below describe the requests each rule sends.
Agent Card discovery tries `/.well-known/agent-card.json` with the v1.0 header,
then without it for v0.3, before checking the older `agent.json` path. Extended
v1.0 card reads send `A2A-Version: 1.0`.

A2A v1.0 restructured the protocol. The v1.0.1 patch fixed specification
inconsistencies without another wire revision. Two details affect this rule set:

- **Task states** are documented in the proto enum form (`TASK_STATE_CANCELED`)
  rather than the lowercase strings (`canceled`) v0.3 used. Detection accepts
  both spellings, since a rule gated on recognizing a task state would otherwise
  go silent against a compliant server.
- **`application/a2a+json`** is now the preferred content type for the HTTP+JSON
  binding. It is a SHOULD rather than a MUST, and the JSON-RPC binding these
  rules primarily drive explicitly keeps `application/json`.

The catalog checks JSON-RPC and advertised HTTP+JSON push-config List/Delete
authorization with a scanner-created config, bounded pagination, and task-access
controls. It also checks task subscription access on both bindings against a
scanner-created nonterminal task, reading one bounded stream response. The
official SDK validation fixture disables streaming and push, so these rules
have local protected and vulnerable fixtures but no live SDK baseline yet.

## Endpoint discovery

The JSON-RPC transport is not required to live at the target root, so discovery
tries advertised JSON-RPC interfaces in preference order, pinned to the target's
own scheme and host. Legacy cards default an omitted `preferredTransport` to
`JSONRPC`. If none answers, discovery probes conventional paths.
Discovery checks at most 16 distinct advertised JSON-RPC URLs.
HTTP+JSON probes likewise try up to 16 advertised bases in order. Their route
prefixes come from the card; they are not inferred from the JSON-RPC URL.

A probed path is judged by a read-only task lookup for a non-existent id, in both
the v0.3 (`tasks/get`) and v1.0 (`GetTask`) spellings. **"Method not found" is
treated as weak evidence**: every JSON-RPC service answers an unknown method that
way, so accepting it meant an MCP server was taken for an A2A agent and the rules
ran against it. When that is all a path offers, it is asked whether it answers an
MCP `initialize`; a valid MCP result disqualifies it.

The check is negative on purpose. A2A agents exist that implement neither
task-get spelling, so requiring a task-shaped answer would lose them. A target
where no A2A endpoint is found is reported as **not tested**, not as clean.

## Clean, or never tested

A rule that finds nothing distinguishes two outcomes, and reports them
differently:

- **Clean.** The target is an A2A agent and this attack did not work against it,
  or the feature the rule targets is absent. A card that advertises no required
  extension leaves `a2a-extension-downgrade-001` nothing to downgrade, and that
  is a real result.
- **Not tested.** Nothing at the target identifies as an A2A agent. Every rule
  reports this rather than a clean pass, because a scan that says "no findings"
  for a host it never exercised claims coverage it does not have.

A target counts as testable when endpoint discovery finds a JSON-RPC endpoint
**or** an agent card is served. Either alone is enough: agents exist that serve
no card, and agents exist whose card is served while their transport is not
where discovery looks.

The three card-analysis rules (`a2a-card-trust-001`, `a2a-jws-algconf-001`,
`a2a-wellknown-hostinject-001`) are stricter, and report **not tested** whenever
no card is served, even against a target that is plainly an agent by other
evidence. A card rule with no card has nothing to say either way.

### Rules that need a task first

Twelve rules cannot say anything until they have created a task: `a2a-task-idor-001`,
`a2a-push-ssrf-001`, `a2a-session-smuggle-001`, `a2a-context-fixation-001`,
`a2a-delegation-integrity-001`, `a2a-multitenant-isolation-001`,
`a2a-push-binding-001`, `a2a-push-lifecycle-001`, `a2a-subscription-scope-001`,
`a2a-task-cancel-idor-001`,
`a2a-task-enumeration-001` and `a2a-push-callback-auth-001`.
Against an agent that enforces authorization, whether they can depends on the
credential the scan was given, so a failure to create one is reported as **not
tested**, naming the refusal and whether the request carried a credential at all. A
clean result there would claim the agent does not leak tasks across principals when no
task ever existed.

Two things stay clean, deliberately. An agent that does not implement the surface
(`-32601`, or A2A's own `-32003` push-not-supported and `-32004`
unsupported-operation) is not applicable rather than untested, the same call the
OAuth-gated MCP rules make for a server exposing no OAuth. And where the request is
one the agent is *supposed* to refuse, that refusal is the pass being looked for:
`a2a-session-smuggle-001` sends a message claiming the agent role, and
`a2a-context-fixation-001` sends a client-chosen `contextId`. For those two, only an
authorization refusal counts as untested.

Note that `a2a-task-idor-001`, `a2a-push-ssrf-001` and `a2a-session-smuggle-001` use
`--token` rather than `--principal`, so a scan that passes only principals will
report them not tested against a secured agent, and say so.

| Rule ID | Attack | Severity | Confidence | CWE |
|---|---|:---:|:---:|---|
| `a2a-extcard-unauth-001` | [Extended Agent Card Unauthenticated Disclosure](#a2a-extcard-unauth-001) | High / Critical | confirmed | CWE-862 |
| `a2a-push-ssrf-001` | [Private Push Callback Delivery](#a2a-push-ssrf-001) | Medium | indicator | CWE-918 |
| `a2a-task-idor-001` | [Anonymous Task Read or List Exposure](#a2a-task-idor-001) | Medium | indicator / policy-confirmed | CWE-639 |
| `a2a-session-smuggle-001` | [Agent Role Injection / Session Smuggling](#a2a-session-smuggle-001) | High | confirmed | CWE-384 |
| `a2a-wellknown-hostinject-001` | [Agent Card Host Header Injection](#a2a-wellknown-hostinject-001) | High / Medium | indicator | CWE-601 |
| `a2a-jws-algconf-001` | [AgentCard JWS Signature Configuration](#a2a-jws-algconf-001) | Critical / High / Medium / Info | indicator | CWE-327 |
| `a2a-peer-impersonation-001` | [Forged JWT Acceptance](#a2a-peer-impersonation-001) | High / Medium | confirmed / indicator | CWE-290 |
| `a2a-artifact-tamper-001` | [Task Artifact Tampering via Task ID Reuse](#a2a-artifact-tamper-001) | Critical | confirmed | CWE-284 |
| `a2a-multitenant-isolation-001` | [Multi-Tenant Task Isolation Breach](#a2a-multitenant-isolation-001) | High | confirmed | CWE-639 |
| `a2a-delegation-integrity-001` | [Delegation Chain-of-Custody Break](#a2a-delegation-integrity-001) | High | confirmed | CWE-863 |
| `a2a-context-fixation-001` | [Context ID Fixation](#a2a-context-fixation-001) | High | confirmed | CWE-384 |
| `a2a-card-trust-001` | [Agent Card Trust Consistency and Cache Policy](#a2a-card-trust-001) | High / Medium / Low | indicator | CWE-345 |
| `a2a-extension-downgrade-001` | [Required-Extension Downgrade / Fail-Open](#a2a-extension-downgrade-001) | High | confirmed | CWE-636 |
| `a2a-push-binding-001` | [Push Config Not Bound to Task Owner](#a2a-push-binding-001) | High | confirmed | CWE-639 |
| `a2a-push-lifecycle-001` | [Push Config List/Delete Outside Task Scope](#a2a-push-lifecycle-001) | High | confirmed | CWE-639 |
| `a2a-subscription-scope-001` | [Subscription and Task-Read Scope Mismatch](#a2a-subscription-scope-001) | High | indicator | CWE-639 |
| `a2a-jsonrpc-batch-bypass-001` | [JSON-RPC Batch Authentication Bypass](#a2a-jsonrpc-batch-bypass-001) | Medium | indicator or confirmed | CWE-288 |
| `a2a-task-cancel-idor-001` | [Cross-Principal Task Cancellation](#a2a-task-cancel-idor-001) | High | indicator / policy-confirmed | CWE-639 / CWE-862 |
| `a2a-task-enumeration-001` | [Cross-Credential Task Listing](#a2a-task-enumeration-001) | Medium | indicator | CWE-639 / CWE-200 |
| `a2a-card-security-unenforced-001` | [Agent Card Declares Unenforced Authentication](#a2a-card-security-unenforced-001) | High | confirmed | CWE-287 / CWE-306 |
| `a2a-push-callback-auth-001` | [Push Notification Missing Webhook Authentication](#a2a-push-callback-auth-001) | High | confirmed | CWE-345 |

---

## Rule Details

### a2a-extcard-unauth-001

**Extended Agent Card Unauthenticated Disclosure** | Severity: High / Critical | CWE-862

Fetches the Extended Agent Card without credentials. It uses v1 JSON-RPC
`GetExtendedAgentCard` and HTTP+JSON `GET /extendedAgentCard`, plus v0.3 JSON-RPC
`agent/getAuthenticatedExtendedCard` and REST `GET /v1/card`. The card carries
privileged capability listings (tools, skills, resource scopes) that should
require authentication. A JSON-RPC `error` envelope or an HTTP 401/403 is
treated as a correct rejection,
not a finding. To avoid noise, outcomes are coalesced to **one finding per
transport** (an invalid-token acceptance is preferred over a no-token acceptance,
since accepting a bogus token is the stronger signal).

This is a confirmed bug in Google's official `a2a-samples` reference
implementation ([issue #340](https://github.com/google-a2a/a2a-samples/issues/340)).

---

### a2a-push-ssrf-001

**Private Push Callback Delivery** | Severity: Medium | indicator

Registers an attacker-controlled URL as a push-notification callback, submits a
task, and waits to see whether the server makes an outbound request to that URL.
Detection is **out-of-band**: by default Batesian starts a local listener and
reports a **medium indicator** when the target actually calls back to its private
address. This proves delivery, not access to another internal service or a policy
violation. Merely accepting a push-notification config is not reported.
Supplying `--oob-url` points the callback at an external collector and emits
operator guidance for manual confirmation.

Three bindings are driven. On **v1.0** the callback is registered through
`CreateTaskPushNotificationConfig` or sent inline as
`configuration.taskPushNotificationConfig` in `SendMessage`. The inline path can
catch callbacks from tasks that finish before a separate registration when
Batesian's local listener can verify delivery. On
**v0.3** it travels inline under `configuration.pushNotificationConfig` and is
also set with `tasks/pushNotificationConfig/set`. The **HTTP+JSON** binding is
driven only when the agent card advertises one, at the URL the card gives: its
prefix is a deployment choice, so there is no path to fall back on and an agent
without that interface is not probed for it.

For confirmed registrations with a returned config ID, the rule attempts
Delete after the probe if readback confirms the callback URL, then records the outcome.
Inline or unidentified configs may remain and are listed in the scan report.
External OOB probes retain configs so delayed callbacks can be verified; remove
them after verification.

A callback can only fire for a task that is still running: a config registered
against a task the agent has already completed has no status update left to
notify on. Against a long-running agent on the official SDK this reports a
callback indicator, with the echoed token as evidence.

Confirmed unfixed in the reference `a2a-python` SDK as of April 2026
([issue #786](https://github.com/google-a2a/a2a-python/issues/786)).

---

### a2a-task-idor-001

**Anonymous Task Read or List Exposure** | Severity: Medium | indicator / policy-confirmed

Reports observed task access using an **auth-enforcement discriminator** so an
open server is not mislabelled. It (1)
creates a task as the authenticated owner, (2) confirms the server *rejects* the
same creation with no credentials, then (3) reads the owner's task from an
unauthenticated connection. It checks JSON-RPC `GetTask` and advertised HTTP+JSON
`GET /tasks/{id}` (v1.0) or `/v1/tasks/{id}` (v0.3). The REST path first confirms
that the owner can read the stored probe text. The finding fires only when creation
was auth-gated yet the unauthenticated read returns that text. The result is an
indicator until the agent's sharing policy establishes that access was forbidden.
An exact `expected_denials` entry for `a2a.tasks.get` or `a2a.tasks.list` with
`caller: anonymous` and `owner: default` provides that policy for the matching
observation.
If anonymous creation succeeds, the server is openly accessible and this rule
stays silent. The rule additionally probes `GET /v1/tasks`
and `/tasks` for unauthenticated server-wide task disclosure. It follows REST
`nextPageToken` cursors for up to ten pages per endpoint; incomplete scans are
inconclusive rather than clean.

**Precondition:** supply `--token` so there is an authenticated owner identity to
test against. Without a token the owner-task read is skipped; the unauthenticated
task-list probe still runs.

---

### a2a-session-smuggle-001

**Agent Role Injection / Session Smuggling** | Severity: High | CWE-384

Sends v1 `SendMessage` (falling back to v0.3 `message/send`) with the agent role,
then **reads the task history back** to confirm whether the injection landed.
Only when the injected message ID and marker are stored as an agent-role turn
is a **confirmed** exploit reported. An agent reply quoting the marker is not proof.

What is reported is the stored turn, not the acceptance. The specification defines
the roles by direction (`ROLE_USER` client-to-server, `ROLE_AGENT` server-to-client)
and carries no MUST or SHOULD requiring a server to validate or reject a
client-supplied role. A client-authored turn
*persisted* under the agent role is the failure, because anything reading that
history back cannot tell it from a genuine agent turn.

A server that rejects the role (`-32602`), normalizes it to `user`, or does not
persist the message is **clean**. When the history cannot be read back, or the reply
carried no task (A2A permits answering a send with a Message), the rule reports **not
tested**: its oracle never ran. That case used to be reported as a high-severity
indicator, which was a finding produced because nothing had been determined.

Demonstrated by Palo Alto Networks Unit 42 (Oct 2025) against a Google ADK sample,
achieving system-prompt exfiltration and an unauthorized action. Cross-session
history disclosure is owned separately by `a2a-task-idor-001`.

---

### a2a-wellknown-hostinject-001

**Agent Card Host Header Injection** | Severity: High / Medium | CWE-601

Requests the agent card with a synthetic canary host (`evil.batesian.invalid`)
injected via `Host`, `X-Forwarded-Host`, `X-Original-Host`, and `X-Forwarded-For`,
then checks where the canary is reflected in the returned card. Severity is graded
by **where** it lands: reflection into an authority/URL field (`url`, `endpoint`,
any `*.url`/`*.uri`, or any value that is itself a URL) is **high / indicator** -
that is the advertised service location peers and registries trust. Reflection
that only lands in a non-URL field (e.g. `description`) is a real injection
primitive but lower direct impact, reported as **medium / indicator**.

---

### a2a-jws-algconf-001

**AgentCard JWS Signature Configuration** | Severity: Critical / High / Medium / Info | CWE-327

A **static analyzer** of the agent card's optional JWS `signatures` field
(RFC 7515). It flags weak signature metadata: `alg: none`,
symmetric algorithms used for public-card verification, empty signature values,
and unprotected or plaintext-HTTP `jku` URLs. A cross-host JWKS is an
informational trust-boundary review, not a vulnerability by itself. The rule
only reads the published card; it never verifies a signature against a client.
Every finding is reported as an **indicator** (severity reflects
impact-if-true, not a demonstrated exploit).

---

### a2a-peer-impersonation-001

**Forged JWT Acceptance** | Severity: High / Medium | CWE-290

Forges an HS256 JWT signed with a random key the server cannot know, claiming to
be a trusted peer agent (`sub`, `iss`, `role`, `aud`), and submits it. The result
is compared against an anonymous baseline. A **confirmed** finding is reported
when the random-key token succeeds but the anonymous request is rejected. This
shows that the token passed the endpoint's gate, not which claim was accepted or
whether peer-specific privileges were granted. If both requests succeed, the
rule reports anonymous access as an **indicator** because public access may be
intentional.

---

### a2a-artifact-tamper-001

**Task Artifact Tampering via Task ID Reuse** | Severity: Critical | CWE-284

Submits a task, then re-submits the same server-returned task ID with different
content, then **reads the task back via `tasks/get`** to prove what the server
actually stored. Acceptance requires HTTP success *and* no JSON-RPC error (a
"task already exists" error is correctly treated as a rejection). A **confirmed**
finding is reported only from the read-back, and only when the tampered
content has fully replaced the original - the stored task returns the attacker's
content alone, which is a critical-severity overwrite. Tampered content appended
alongside the original means the original was preserved - a conformant
continuation, and no finding. If the re-submission is accepted but the stored
result cannot be read back, nothing was determined and the rule reports **not
tested**.

---

### a2a-multitenant-isolation-001

**Multi-Tenant Task Isolation Breach** | Severity: High | CWE-639

A **stateful, multi-principal chained** rule (the first to use the chaining
engine). Unlike `a2a-task-idor-001` (anonymous access), this confirms that a
*fully authenticated* principal in one tenant cannot read another tenant's task.
It requires **two principals with valid, distinct credentials**, configured via
the `principals:` block in `batesian.yaml` or repeated `--principal
name=...,token=...,tenant=...` flags.
Both principals also need nonempty, distinct tenant labels. These labels are
operator-supplied; verify that they match the target's actual tenant assignments.

Sequence: (1) authenticate as A and B and have each create its own task; (2)
confirm each owner can read its unique probe text, since task history is not
guaranteed to persist every message; (3) check anonymous access so public
content is not mislabeled as a tenant breach; (4) read across tenants in both
directions. A **confirmed** finding requires the other principal to retrieve the
owner's probe text with its own valid credentials. An unverified owner read is
reported as incomplete for that direction, while the other direction can still
produce a finding.

The rule tests JSON-RPC and advertised HTTP+JSON `POST /message:send` and
`GET /tasks/{id}` routes, with `/v1` prefixes for v0.3. REST reads request up
to ten history messages. JSON-RPC tasks can feed chained rules; REST tasks are
tested separately and are not reused across bindings.

---

### a2a-delegation-integrity-001

**Delegation Chain-of-Custody Break (Wrong-Principal Continuation)** | Severity: High | CWE-863

A **chained CONSUMER** rule - the first rule that consumes another rule's
blackboard output. It declares `Requires(task-id)`, so the engine runs it
after any task-id producer (e.g. `a2a-multitenant-isolation-001`) and it reuses
that upstream task-id; run standalone it falls back to creating its own delegator
task. Needs two principals with valid, distinct credentials.

It tests whether a delegated / multi-hop task is re-bound to its owning principal
on each hop. It obtains A's task, sends an unauthenticated control message, then
sends a unique follow-up as principal B. A **confirmed** finding requires that
B's user-role message text appear in A's task history when read back as A,
regardless of the send response. A response that
only names A's task or shares its `contextId` is insufficient: it may be a
no-op or a new task. If A's history cannot verify an accepted send, the result
is inconclusive. If the unauthenticated message is stored, the rule leaves the
case to the unauthenticated task-access checks. The finding proves stored
cross-principal input, not downstream execution or absence of a valid delegation
grant. Its provenance records whether A's task came from an upstream rule.

---

### a2a-context-fixation-001

**Context ID Fixation (Client-Supplied contextId Across Principals)** | Severity: High | CWE-384

The A2A half of the session/task-ID fixation concern (the MCP half is
`mcp-session-fixation-001`). A2A groups a conversation by `contextId`; the
v1 specification permits client-provided IDs. Accepting one is not a finding by
itself; the server must scope the context to its authorized participants. This **chained,
multi-principal** rule confirms a server that accepts a client-chosen contextId
**and** exposes a different principal's messages under it. Needs two principals
with valid, distinct credentials.

Sequence: (1) as attacker A, send under a client-chosen contextId - if the server
returns a different contextId, this rule cannot establish the leak; (2)
confirm an unauthenticated message under the fixed context is rejected on the
same protocol wire (else it is open or untested); (3) as victim B, send a secret
marker under the same contextId and confirm B's task reports it; (4) as A, read
the context back. A **confirmed** finding requires B's marker in A's requested
task history, not response metadata or another task.
The read-back must match the request and task IDs. A clean result also requires
A's own marker in that history; missing history is inconclusive. Distinct from
`a2a-multitenant-isolation-001`
(object-level read by task id) and `a2a-delegation-integrity-001` (continuing
another principal's task): here the vector is the client-controlled context
identifier itself.

---

### a2a-card-trust-001

**Agent Card Trust Consistency and Cache Policy** | Severity: High / Medium / Low | CWE-345

Covers the agent-card trust gaps the other card rules do not: where
`a2a-jws-algconf-001` inspects the signature *algorithm*,
`a2a-wellknown-hostinject-001` inspects Host reflection, and
`a2a-extcard-unauth-001` inspects unauthenticated access, this rule inspects how
*durable and consistent* the card's trust is. Because Batesian scans the server
(not a consuming verifier), it judges only what the server exposes - two
checks:

- **Canonicalization / multi-path consistency.** The card is fetched from both
  `/.well-known/agent-card.json` and the legacy `/.well-known/agent.json`. If one
  path serves a **signed** card and the other an **unsigned** one, an attacker can
  steer verification to the unsigned path to strip the signature requirement -
  reported **indicator (high)**. Otherwise, comparable preferred interfaces
  with different endpoint URLs (`supportedInterfaces[0].url` in v1, top-level
  `url` in v0.3)
  produce a **medium indicator** (routing ambiguity). Different card shapes or
  preferred interface bindings, versions, or tenants are not compared. Missing
  preferred endpoint fields on either served card also produce a **medium
  indicator**.
- **Stale-cache trust.** A long `max-age`, applicable `s-maxage`, or `Expires`
  lifetime (>= 1h) without unqualified `no-store`/`no-cache` can keep the trust
  anchor cached after key rotation or compromise (**indicator, medium**).
  `Expires` uses the response `Date` (or receipt time when absent) and is ignored
  where `max-age` applies. A short `s-maxage` does not override `Expires` for
  private caches. `immutable` without explicit freshness, or a response with
  neither `Cache-Control` nor `Expires`, is a weaker freshness-uncertainty
  **indicator (low)**.
  `immutable` does not extend a short freshness lifetime.
  Both well-known paths are checked when served; the highest-severity cache
  finding is reported, preferring the primary path on ties.
  Unqualified `no-store`/`no-cache` produce no finding; qualified `no-cache`
  only restricts the listed header fields, not reuse of the card body.
  `max-age=0` is clean unless a long `s-maxage` keeps shared caches fresh.
  Unqualified `private` disables shared caching. `must-revalidate` applies only
  after a cached response becomes stale, so it does not cancel a long freshness
  lifetime.

The A2A JWS protected header does not require `exp`. Card signatures without it
are not reported; key expiry and revocation depend on the verifier's key source.

---

### a2a-extension-downgrade-001

**Required-Extension Downgrade / Fail-Open** | Severity: High | CWE-636

A2A agent cards advertise protocol extensions under `capabilities.extensions[]`,
each with a `uri` and a `required` flag; clients activate one via the
`A2A-Extensions` request header (the legacy `X-A2A-Extensions` name, used through
v0.3.0, is also sent for older servers). A required extension is a capability the
server states clients must activate, so the spec requires the server to reject
requests that do not (`ExtensionSupportRequiredError`). This rule is card-driven
and confirms a fail-open downgrade only with a control/test pair: it reads the
card, and for each `required: true` extension it (1) sends a message that
**activates** the extension (control - must be accepted or the rule can't test),
then (2) sends the same wire shape with both extension headers **omitted**. The
v0.3 fallback uses `message/send` without a v1 version header. A **confirmed**
finding requires the omission to be accepted too - the server does not enforce
its own required extension, so its policy/capability guarantees can be bypassed
by omitting both headers. A server that rejects the un-activated request fails
closed (no finding). Malformed `capabilities.extensions` entries cannot establish the
card's required-extension policy and make this check inconclusive.

---

### a2a-push-binding-001

**Push Config Not Bound to Task Owner** | Severity: High | CWE-639

The rule creates or reuses an authenticated principal's task, stores a marker
push config, and verifies it through the owner's readback. It then checks whether
an anonymous caller can store a different callback on that task, but only after
confirming anonymous task read is denied. A persisted anonymous write is reported
with one configured principal. If that write does not persist, two distinct
principals enable cross-principal read and write checks. The second principal
must be denied task read access first; a shared task or unjudged task read is
not treated as an ownership breach. Findings require the owner's marker URL or
an owner-confirmed write, respectively.

The rule supports v1.0's flat `TaskPushNotificationConfig` and v0.3's nested
`pushNotificationConfig` over JSON-RPC and advertised HTTP+JSON bindings.
The REST checks use `POST /tasks/{id}/pushNotificationConfigs` and
`GET /tasks/{id}/pushNotificationConfigs/{configId}`, with `/v1` prefixes for
v0.3. The rule does not test notification delivery or gRPC.
It attempts to delete each accepted marker after the task owner's readback
confirms its callback URL. Unconfirmed markers or refused deletions remain in
the scan report. On single-config servers, a marker can replace an existing
callback on a reused task; use test tasks for this rule.

---

### a2a-push-lifecycle-001

**Push Config List/Delete Outside Task Scope** | Severity: High | CWE-639

Creates an owner task and push config, confirms the owner can read both, and
requires the second principal to be denied task access before judging it as
unauthorized. It then checks whether that principal can list the marker or
delete it. A List finding requires the marker ID and URL in a correlated
response. A Delete finding requires a correlated success and owner readback
showing the marker is gone while the task still exists. The rule follows up to
eight v1.0 list pages and detects repeated page tokens. It never deletes a
pre-existing config and records cleanup of the scanner-created one.

The rule supports v1.0 and v0.3 JSON-RPC and advertised HTTP+JSON bindings,
including `GET /tasks/{id}/pushNotificationConfigs` and
`DELETE /tasks/{id}/pushNotificationConfigs/{configId}` (with `/v1` prefixes on
v0.3). It does not cover gRPC. If the second principal can read the task, the
access relationship is ambiguous and the rule reports not tested.

---

### a2a-subscription-scope-001

**Subscription and Task-Read Scope Mismatch** | Severity: High | CWE-639

Creates a nonterminal task as one principal and requires that principal to read
and subscribe to it. A second principal must be denied task read access before
the rule tests whether it receives the same task and context in a subscription
event. The rule captures one bounded response event, then closes the stream.
It expects a task snapshot on v1.0; v0.3 may start with a task or
status/artifact update. A missing task,
terminal task, malformed stream, or ambiguous access control is not reported as
clean. Task identifiers and stream content are omitted from findings. Because
the agent may intentionally grant subscription without task-read access, a
matching stream is an **indicator** to review against its authorization policy.

The rule tests v1.0 and v0.3 JSON-RPC and advertised HTTP+JSON bindings, but not
gRPC. It requires two distinct configured principals and creates a task on the
target.

---

### a2a-jsonrpc-batch-bypass-001

**JSON-RPC Batch Authentication Bypass** | Severity: Medium baseline, High when confirmed | CWE-288

The rule sends the same unauthenticated `GetTask` request as a single object and
as a one-element batch. It probes v1.0 `GetTask` and then v0.3 `tasks/get`, using
distinct IDs for each shape. The control must return HTTP 401/403 or a correlated
JSON-RPC auth error. A batch reply with a correlated task object confirms access
despite that refusal. A correlated `TaskNotFound` is only a risk indicator because
A2A also uses it for inaccessible tasks. The probe uses a random, non-existent
task ID and does not mutate state. [JSON-RPC 2.0 permits batches](https://www.jsonrpc.org/specification#batch);
servers that accept them must apply the same authentication and authorization
checks as for single requests.

---

### a2a-task-cancel-idor-001

**Cross-Principal Task Cancellation** | Severity: High | indicator / policy-confirmed

Tests whether task cancellation (`CancelTask` / `tasks/cancel`, plus the advertised
HTTP+JSON `POST /tasks/{id}:cancel` or v0.3 `/v1/tasks/{id}:cancel`) is bound to the
task's owner. Cancellation is a distinct handler from reading a task
(`a2a-task-idor-001`) or continuing it (`a2a-delegation-integrity-001`) and can be
left unprotected on its own, giving an attacker a targeted way to terminate other
principals' tasks. Needs two authenticated principals and reports two observed
cancellation outcomes:

- **Unauthenticated cancellation (CWE-862).** The rule creates a task as A, then
  cancels it with no credentials. A matching successful cancel reply and an
  owner read-back showing `canceled` confirm the action occurred.
- **Cross-principal cancellation (CWE-639).** If the unauthenticated cancel is
  rejected (so auth is enforced), the rule cancels A's task as the wrong principal
  B. An **indicator** is raised only when B's cancel returns a matching
  success and a read-back as owner A shows the task is now `canceled`.

A denial followed by an independently canceled task is inconclusive. A successful
cross-principal cancellation is not called IDOR without a policy that forbids B's
access to A's task. An exact `expected_denials` entry for `a2a.tasks.cancel`
can confirm the observed cancellation when it names the denied caller and owner.

A server that rejects the wrong-principal cancel produces no finding: the
boundary was tested and held. Two outcomes are not clean results: an anonymous
cancel answered with an application error (task hidden from anonymous callers,
task already terminal) never established whether the cancel handler demands a
credential, so the rule reports **not tested**; and a server implementing no
cancel method on either wire is not applicable. The rule creates and cancels its
own throwaway task; it never cancels a pre-existing one. Against a server that
completes tasks almost immediately, the probe task may be terminal before it can
be canceled, in which case the rule reports not tested.

---

### a2a-card-security-unenforced-001

**Agent Card Declares Unenforced Authentication** | Severity: High | CWE-287 / CWE-306

The AgentCard is a machine-readable contract: its `securitySchemes` plus a
requirements list (named `security` in v0.3 cards, `securityRequirements` in v1.0
proto-JSON cards - both are read) declare which authentication a caller MUST
present. This rule fires only when the card declares a **non-empty** requirement
with **no anonymous alternative** (an empty `{}` requirement object, per OpenAPI
convention, explicitly permits anonymous access and is not flagged), then sends an
unauthenticated core request. A first, non-mutating `tasks/get` for a random
non-existent id records whether the read path is reachable anonymously; the
definitive confirmation is an unauthenticated send that returns a valid Task or
direct agent Message. A created Task is read back to corroborate it. The rule
checks advertised HTTP+JSON interfaces as well as JSON-RPC. Malformed replies,
request echoes, and ambiguous application errors do not trigger a finding. A
server that answers the unauthenticated request with HTTP 401/403 produces no
finding.

This complements `a2a-task-idor-001`, which keys off whether anonymous creation is
rejected and **suppresses** its finding when the server enforces no authentication
at all - so a wide-open agent goes unflagged there. This rule flags exactly that
case, but only when the card promised authentication, making it an attributable
contract violation (CWE-287 / CWE-306). It is distinct from `a2a-extcard-unauth-001`
(the extended-card endpoint) and `a2a-card-trust-001` / `a2a-jws-algconf-001` (card
signatures).

---

### a2a-task-enumeration-001

**Cross-Credential Task Listing** | Severity: Medium | CWE-639 / CWE-200

Tests whether a task created with one credential appears in `ListTasks` under
another. A2A requires each client to see only tasks authorized by the agent's
access policy. Different credentials alone do not prove that their task visibility
must differ, so the result is an **indicator** for policy review.

**A distinct surface**, not a second look at an existing one.
`a2a-multitenant-isolation-001` reads a task **by id**, so it only shows that a caller
who already knows an identifier can fetch it. `a2a-task-idor-001` probes the REST list
paths **anonymously**, so a server that correctly requires a credential passes it and
can still hand every tenant's tasks to any authenticated caller. The listing is
separate code from the per-task fetch, and a server can scope one and not the other:
the fetch has an obvious owner to compare against, while the list has to be filtered.

Two principals are required, and three controls keep it off servers where the listing
is not what decided the outcome:

1. Principal A creates a task. A refused creation is reported as **not tested**, naming
   the refusal, rather than as a scoped listing that was never given anything to leak.
2. Control: A lists its own tasks and must see the task it just created. An absent
   list method or REST path is **clean** for that binding. A refused list or one
   missing the owner's task is **not tested**: B seeing nothing proves nothing.
3. Control: an **unauthenticated** `ListTasks`. If it returns A's task, the server
   enforces no authorization on this surface at all, which is `a2a-task-idor-001`'s
   finding; reporting it here too would count one defect twice.
4. Principal B lists. A's task ID appearing in B's response is the indicator.

Identifiers are compared, never key names, and history is deliberately not requested
(`historyLength` 0). The rule follows
`nextPageToken` for up to ten pages per caller. A repeated token, failed page, or
page limit makes the result not tested rather than clean.

The rule probes v1.0 JSON-RPC `ListTasks` and the HTTP+JSON task list at each
advertised REST base: `/tasks` for v1.0 and `/v1/tasks` for v0.3. It creates a
task through the same binding before checking its listing. REST prefixes come
from the agent card and are pinned to the target origin, not guessed.

---

### a2a-push-callback-auth-001

**Push Notification Missing Webhook Authentication** | Severity: High | confirmed | CWE-345

Registers a push callback with a generated Bearer credential, then checks a
task notification for the matching `Authorization` header. The URL marker,
push token, and Bearer credential are distinct. A missing or mismatched
credential on an observed task notification is a confirmed finding; no
callback is inconclusive. The rule tries the same JSON-RPC and HTTP+JSON
registration paths as `a2a-push-ssrf-001`, including v1.0 inline configuration.
With an external `--oob-url`, registration is informational and delivery needs
manual verification. The rule attempts to delete confirmed configs with
returned IDs after readback confirms the callback URL. Inline or unidentified
configs may remain. External OOB probes retain configs for manual verification.
A refused task creation is not tested.
