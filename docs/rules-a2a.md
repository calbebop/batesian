# A2A Attack Rules

Batesian ships **18 rules** targeting the [Agent-to-Agent (A2A) protocol](https://a2a-protocol.org/).
Every rule is an active probe: it sends crafted protocol traffic and judges the
server's actual response. Rules are deliberately scoped to A2A-specific semantics
(agent cards, JWS card signatures, tasks/contexts, push notifications, peer
identity) rather than generic web hygiene.

Each finding carries a **confidence**:

- **confirmed** - the attack was demonstrably successful (e.g. the tampered value
  was read back, the forged token was accepted against a rejecting baseline).
- **indicator** - a suspicious posture was observed but exploitation could not be
  proven from the response alone; manual verification is recommended.

## Protocol currency

These rules target **A2A v1.0** (the current released version, v1.0.1 as of this
writing) and fall back to the **v0.3** shapes where they differ, so a deployment
on either revision is exercised. In practice that means sending the v1.0
PascalCase methods with the `A2A-Version: 1.0` header first and retrying with the
v0.3 slash methods, and reading both the v1.0 `securityRequirements` and the v0.3
`security` field from an agent card.

Unlike MCP, A2A has had no restructuring revision: v1.0.1 is a patch that fixed
specification inconsistencies rather than changing the protocol. Two of its
changes touch this rule set:

- **Task states** are documented in the proto enum form (`TASK_STATE_CANCELED`)
  rather than the lowercase strings (`canceled`) v0.3 used. Detection accepts
  both spellings, since a rule gated on recognizing a task state would otherwise
  go silent against a compliant server.
- **`application/a2a+json`** is now the preferred content type for the HTTP+JSON
  binding. It is a SHOULD rather than a MUST, and the JSON-RPC binding these
  rules primarily drive explicitly keeps `application/json`.

## Endpoint discovery

The JSON-RPC transport is not required to live at the target root, so discovery
prefers the URL the agent card declares for the JSON-RPC interface, pinned to the
target's own scheme and host. Only when no card names one does it probe the
conventional paths.

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

Nine rules cannot say anything until they have created a task: `a2a-task-idor-001`,
`a2a-push-ssrf-001`, `a2a-session-smuggle-001`, `a2a-context-fixation-001`,
`a2a-delegation-integrity-001`, `a2a-multitenant-isolation-001`,
`a2a-push-binding-001`, `a2a-task-cancel-idor-001` and `a2a-task-enumeration-001`.
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
| `a2a-extcard-unauth-001` | [Extended Agent Card Unauthenticated Disclosure](#a2a-extcard-unauth-001) | High | confirmed | CWE-862 |
| `a2a-push-ssrf-001` | [Push Notification SSRF](#a2a-push-ssrf-001) | High | confirmed | CWE-918 |
| `a2a-task-idor-001` | [Task IDOR via Unauthenticated tasks/get](#a2a-task-idor-001) | High | confirmed | CWE-639 |
| `a2a-session-smuggle-001` | [Agent Role Injection / Session Smuggling](#a2a-session-smuggle-001) | High | confirmed | CWE-384 |
| `a2a-wellknown-hostinject-001` | [Agent Card Host Header Injection](#a2a-wellknown-hostinject-001) | High / Medium | indicator | CWE-601 |
| `a2a-jws-algconf-001` | [AgentCard JWS Algorithm Confusion](#a2a-jws-algconf-001) | Critical | indicator | CWE-327 |
| `a2a-peer-impersonation-001` | [Peer Agent Impersonation via Forged JWT](#a2a-peer-impersonation-001) | Critical | confirmed | CWE-290 |
| `a2a-artifact-tamper-001` | [Task Artifact Tampering via Task ID Reuse](#a2a-artifact-tamper-001) | High | confirmed | CWE-284 |
| `a2a-multitenant-isolation-001` | [Multi-Tenant Task Isolation Breach](#a2a-multitenant-isolation-001) | High | confirmed | CWE-639 |
| `a2a-delegation-integrity-001` | [Delegation Chain-of-Custody Break](#a2a-delegation-integrity-001) | High | confirmed | CWE-863 |
| `a2a-context-fixation-001` | [Context ID Fixation](#a2a-context-fixation-001) | High | confirmed | CWE-384 |
| `a2a-card-trust-001` | [Agent Card Trust Durability](#a2a-card-trust-001) | High / Medium | indicator | CWE-345 |
| `a2a-extension-downgrade-001` | [Required-Extension Downgrade / Fail-Open](#a2a-extension-downgrade-001) | High | confirmed | CWE-636 |
| `a2a-push-binding-001` | [Push/Webhook Control-Plane Not Bound to Task Owner](#a2a-push-binding-001) | High | confirmed | CWE-639 |
| `a2a-jsonrpc-batch-bypass-001` | [JSON-RPC Batch Authentication Bypass](#a2a-jsonrpc-batch-bypass-001) | High | confirmed | CWE-288 |
| `a2a-task-cancel-idor-001` | [Cross-Principal Task Cancellation](#a2a-task-cancel-idor-001) | High | confirmed | CWE-639 / CWE-862 |
| `a2a-task-enumeration-001` | [ListTasks Enumerates Another Principal's Tasks](#a2a-task-enumeration-001) | High | confirmed | CWE-639 / CWE-200 |
| `a2a-card-security-unenforced-001` | [Agent Card Declares Unenforced Authentication](#a2a-card-security-unenforced-001) | High | confirmed | CWE-287 / CWE-306 |

---

## Rule Details

### a2a-extcard-unauth-001

**Extended Agent Card Unauthenticated Disclosure** | Severity: High | CWE-862

Fetches the Extended Agent Card without credentials, over both transports the spec
allows: the JSON-RPC `agent/getAuthenticatedExtendedCard` method and the legacy
`GET /extendedAgentCard` endpoint. The extended card carries privileged capability
listings (tools, skills, resource scopes) that should require authentication. A
JSON-RPC `error` envelope or an HTTP 401/403 is treated as a correct rejection,
not a finding. To avoid noise, outcomes are coalesced to **one finding per
transport** (an invalid-token acceptance is preferred over a no-token acceptance,
since accepting a bogus token is the stronger signal).

This is a confirmed bug in Google's official `a2a-samples` reference
implementation ([issue #340](https://github.com/google-a2a/a2a-samples/issues/340)).

---

### a2a-push-ssrf-001

**Push Notification SSRF** | Severity: High | CWE-918

Registers an attacker-controlled URL as a push-notification callback, submits a
task, and waits to see whether the server makes an outbound request to that URL.
Detection is **out-of-band**: by default Batesian starts a local listener and only
reports a **confirmed** SSRF when the target actually calls back. Merely accepting
a push-notification config is normal A2A behaviour and is **not** reported.
Supplying `--oob-url` points the callback at an external collector and emits
operator guidance for manual confirmation.

Three bindings are driven. On **v1.0** the callback is registered through
`CreateTaskPushNotificationConfig`, whose params are a `TaskPushNotificationConfig`
carrying a flat `url`; there is no way to attach one to a send, because
`SendMessageConfiguration` has no such field. On **v0.3** it travels inline on
`message/send` under `configuration.pushNotificationConfig`, and is also set
explicitly with `tasks/pushNotificationConfig/set`. The **HTTP+JSON** binding is
driven only when the agent card advertises one, at the URL the card gives: its
prefix is a deployment choice, so there is no path to fall back on and an agent
without that interface is not probed for it.

A callback can only fire for a task that is still running: a config registered
against a task the agent has already completed has no status update left to
notify on. Against a long-running agent on the official SDK this reports a
confirmed finding, with the echoed token as evidence.

Confirmed unfixed in the reference `a2a-python` SDK as of April 2026
([issue #786](https://github.com/google-a2a/a2a-python/issues/786)).

---

### a2a-task-idor-001

**Task IDOR via Unauthenticated tasks/get** | Severity: High | CWE-639

Detects broken object-level authorization (IDOR / BOLA) on task lookup using an
**auth-enforcement discriminator** so an open server is not mislabelled. It (1)
creates a task as the authenticated owner, (2) confirms the server *rejects* the
same creation with no credentials, then (3) reads the owner's task from an
unauthenticated connection. The finding fires only when creation was auth-gated
yet the unauthenticated read still returns the task. If anonymous creation
succeeds, the server enforces no auth at all and no IDOR finding is raised (that
posture belongs to other checks). The rule additionally probes `GET /v1/tasks`
and `/tasks` for unauthenticated server-wide task disclosure.

**Precondition:** supply `--token` so there is an authenticated owner identity to
test against. Without a token the IDOR step is skipped; the unauthenticated
task-list probe still runs.

---

### a2a-session-smuggle-001

**Agent Role Injection / Session Smuggling** | Severity: High | CWE-384

Sends a `message/send` request with `role: agent`, then **reads the task history
back** to confirm whether the injection landed. Only when the marker is stored as an
agent-role turn is a **confirmed** exploit reported.

What is reported is the stored turn, not the acceptance. The specification defines
the roles by direction (`ROLE_USER` client-to-server, `ROLE_AGENT` server-to-client)
and carries no MUST or SHOULD requiring a server to validate or reject a
client-supplied role; both official SDKs accept one. A client-authored turn
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

**AgentCard JWS Algorithm Confusion** | Severity: Critical | CWE-327

A **static analyzer** of the agent card's optional JWS `signatures` field
(RFC 7515). It flags structural weaknesses that enable card forgery: `alg: none`,
symmetric algorithms used for public-card verification, empty signature values,
and `jku` URLs that are unprotected or cross-domain. Because the rule only reads
the published card - it never forges or verifies a signature against the live
server - every finding is reported as an **indicator** (severity reflects
impact-if-true, not a demonstrated exploit).

---

### a2a-peer-impersonation-001

**Peer Agent Impersonation via Forged JWT** | Severity: Critical | CWE-290

Forges an HS256 JWT signed with a random key the server cannot know, claiming to
be a trusted peer agent (`sub`, `iss`, `role`, `aud`), and submits it. The result
is compared against an unauthenticated baseline. A **confirmed** authentication
bypass is reported only when the forged token is accepted while the baseline is
rejected - where "rejected" includes both HTTP 401/403 and a JSON-RPC `error`
envelope (so servers that reject auth at the protocol layer are not false
negatives). If both forged and unauthenticated requests succeed, the server has no
authentication at all and a lower-severity finding is raised instead.

---

### a2a-artifact-tamper-001

**Task Artifact Tampering via Task ID Reuse** | Severity: High | CWE-284

Submits a task, then re-submits the same client-generated task ID with different
content, then **reads the task back via `tasks/get`** to prove what the server
actually stored. Acceptance requires HTTP success *and* no JSON-RPC error (a
"task already exists" error is correctly treated as a rejection). A **confirmed**
finding is reported only from the read-back: tampered content replacing the
original is a critical overwrite; tampered content appended alongside the original
is high-severity injection. If the re-submission is accepted but the original is
preserved, no finding is raised; if accepted but the result cannot be verified, an
**indicator** is reported.

---

### a2a-multitenant-isolation-001

**Multi-Tenant Task Isolation Breach** | Severity: High | CWE-639

A **stateful, multi-principal chained** rule (the first to use the chaining
engine). Unlike `a2a-task-idor-001` (anonymous access), this confirms that a
*fully authenticated* principal in one tenant cannot read another tenant's task.
It requires **two principals with valid, distinct credentials**, configured via
the `principals:` block in `batesian.yaml` or repeated `--principal
name=...,token=...,tenant=...` flags.

Sequence: (1) authenticate as A and B and have each create its own task - both
must succeed, proving two valid distinct identities (shared tokens => skip); (2)
confirm the server is not simply open - an unauthenticated read of A's task must
be rejected (if it succeeds, that's `a2a-task-idor-001` territory, not a tenant
breach, so no finding here); (3) attempt the cross-tenant reads in both
directions. A **confirmed** finding is raised only when a principal retrieves the
other tenant's task content using its own valid credentials, with a hop-by-hop
provenance trail attached to the finding.

---

### a2a-delegation-integrity-001

**Delegation Chain-of-Custody Break (Wrong-Principal Continuation)** | Severity: High | CWE-863

A **chained CONSUMER** rule - the first rule that consumes another rule's
blackboard output. It declares `Requires(task-id)`, so the engine runs it
after any task-id producer (e.g. `a2a-multitenant-isolation-001`) and it reuses
that upstream task-id; run standalone it falls back to creating its own delegator
task. Needs two principals with valid, distinct credentials.

It tests whether a delegated / multi-hop task is re-bound to its owning principal
on each hop. Sequence: (1) obtain a task owned by delegator A (from the
blackboard or by creating one); (2) confirm the server enforces auth - an
unauthenticated continuation of A's task must be rejected (otherwise it's
`a2a-task-idor-001` territory, not a delegation break, so no finding); (3)
continue A's task as the WRONG principal B (a follow-up message carrying A's
taskId/contextId presented with B's credentials). A **confirmed** finding is
raised only when B successfully advances A's task, proving the delegated step is
not re-bound to the owning principal. The finding's provenance records whether
the task was consumed from an upstream rule or created locally.

---

### a2a-context-fixation-001

**Context ID Fixation (Client-Supplied contextId Across Principals)** | Severity: High | CWE-384

The A2A half of the session/task-ID fixation concern (the MCP half is
`mcp-session-fixation-001`). A2A groups a conversation by `contextId`; the
server should mint it and scope each context to its participants. This **chained,
multi-principal** rule confirms a server that adopts a client-chosen contextId
**and** merges a different principal's messages under it. Needs two principals
with valid, distinct credentials.

Sequence: (1) as attacker A, send under a client-chosen contextId - if the server
returns its own contextId instead, it mints server-side, so no finding; (2)
confirm an unauthenticated message under the fixed context is rejected (else it's
an open server, not fixation); (3) as victim B, send a secret marker under the
same contextId; (4) as A, read the context back. A **confirmed** finding is
raised only when A can see B's marker - proving the pre-seeded contextId merged
the two principals' conversations. Distinct from `a2a-multitenant-isolation-001`
(object-level read by task id) and `a2a-delegation-integrity-001` (continuing
another principal's task): here the vector is the client-controlled context
identifier itself.

---

### a2a-card-trust-001

**Agent Card Trust Durability (Canonicalization, Cache, Signature Freshness)** | Severity: High / Medium | CWE-345

Covers the agent-card trust gaps the other card rules do not: where
`a2a-jws-algconf-001` inspects the signature *algorithm*,
`a2a-wellknown-hostinject-001` inspects Host reflection, and
`a2a-extcard-unauth-001` inspects unauthenticated access, this rule inspects how
*durable and consistent* the card's trust is. Because Batesian scans the server
(not a consuming verifier), it judges only what the server exposes - three
checks:

- **Canonicalization / multi-path consistency.** The card is fetched from both
  `/.well-known/agent-card.json` and the legacy `/.well-known/agent.json`. If one
  path serves a **signed** card and the other an **unsigned** one, an attacker can
  steer verification to the unsigned path to strip the signature requirement -
  reported **indicator (high)**. If both are signed but their `url` differs,
  reported as an **indicator (medium)** (routing ambiguity).
- **Stale-cache trust.** The card response's `Cache-Control` is parsed. A long
  `max-age` (>= 1h) or `immutable` without `no-cache`/`must-revalidate` keeps the
  trust anchor cached after key rotation or compromise (**indicator, medium**); a
  missing `Cache-Control` is a weaker heuristic-caching **indicator (low)**.
  `no-store`/`no-cache`/`must-revalidate`/`max-age=0` produce no finding.
- **Signature freshness.** When the card carries signatures, each protected
  header is decoded: no `exp` means the signature never expires (**indicator,
  medium**); an `exp` already in the past that is still served is an **indicator**
  (a compliant verifier rejects an expired signature).

---

### a2a-extension-downgrade-001

**Required-Extension Downgrade / Fail-Open** | Severity: High | CWE-636

A2A agent cards advertise protocol extensions under `capabilities.extensions[]`,
each with a `uri` and a `required` flag; clients activate one via the
`A2A-Extensions` request header (the legacy `X-A2A-Extensions` name, used through
v0.3.0, is also sent for older servers). A required extension is a capability the
server states clients must activate, so the spec requires the server to reject
requests that do not (`ExtensionSupportRequiredError`). This rule is card-driven and confirms a fail-open downgrade only with a
control/test pair: it reads the card, and for each `required: true` extension it
(1) sends a `SendMessage` that **activates** the extension (control - must be
accepted or the rule can't test), then (2) sends an identical `SendMessage` with
the `A2A-Extensions` header **omitted**. A **confirmed** finding is raised only
when the omission is also accepted - the server does not enforce its own required
extension, so its policy/capability guarantees can be bypassed by simply not
sending the header. A server that rejects the un-activated request fails closed
(no finding).

---

### a2a-push-binding-001

**Push/Webhook Control-Plane Not Bound to Task Owner** | Severity: High | CWE-639

Extends `a2a-push-ssrf-001` (callback SSRF, a data-plane test) to the push
**control plane**: who may attach or read a webhook on whose task. This is a
stateful, multi-principal chained rule (it consumes an upstream task-id when
present, else creates its own) and needs two valid, distinct principals.
Sequence: (1) as owner A, obtain a task and set a push-notification config with a
unique marker URL (control - must succeed or the feature is absent); (2)
discriminator - an unauthenticated set on A's task must be rejected, else the
control plane has no auth at all (no finding); (3) as a different principal B,
**read** A's push config (a **confirmed** callback-secret leak if B's response
echoes A's marker URL) and **set** a push config on A's task (a **confirmed**
webhook hijack if accepted). Distinct from `a2a-multitenant-isolation-001`
(reading another tenant's task) and `a2a-delegation-integrity-001` (continuing
another principal's task): here the vector is the push-config API itself, which
can redirect a victim task's results to an attacker URL.

The config is written in whichever shape the deployment takes: on **v1.0** the
params to `CreateTaskPushNotificationConfig` are themselves a
`TaskPushNotificationConfig`, so the callback is a flat `url`, while **v0.3**
nests it under `pushNotificationConfig` on `tasks/pushNotificationConfig/set`.

---

### a2a-jsonrpc-batch-bypass-001

**JSON-RPC Batch Authentication Bypass** | Severity: High | CWE-288

Tests whether authentication can be bypassed by wrapping a request in a JSON-RPC
batch array. The gate inspects the top-level request object, but a batch is an
array with no top-level method, so the check does not fire and the dispatcher runs
each element. A2A enforces auth at the HTTP layer, so the bypass shows up as a
single request rejected at the transport (HTTP 401/403) while the identical
request, batch-wrapped, reaches HTTP 200 and is dispatched. Detection sends the
**identical** request twice (single object then one-element array) for each
protocol shape (v1.0 `GetTask`, then the v0.3 `tasks/get` fallback). A
**confirmed** finding is raised only when the single object is rejected with
401/403 but the batch reaches 200 and the dispatcher ran (the batch response
carries a result or a non-auth application error such as `TaskNotFound`). The
probe is a read-only `GetTask` for a non-existent task id, so nothing is sent,
created, or mutated. A2A does not define batching, so a correct server should
reject the array rather than dispatch it unauthenticated (CWE-288).

---

### a2a-task-cancel-idor-001

**Cross-Principal Task Cancellation** | Severity: High | CWE-639 / CWE-862

Tests whether task cancellation (`CancelTask` / `tasks/cancel`) is bound to the
task's owner. Cancellation is a distinct handler from reading a task
(`a2a-task-idor-001`) or continuing it (`a2a-delegation-integrity-001`) and can be
left unprotected on its own, giving an attacker a targeted way to terminate other
principals' tasks. Needs two authenticated principals and reports two confirmed
failures:

- **Unauthenticated cancellation (CWE-862).** The rule creates a task as A, then
  cancels it with no credentials. If that cancel is accepted (the task becomes
  `canceled`), authentication is missing on a state-changing operation.
- **Cross-principal cancellation (CWE-639).** If the unauthenticated cancel is
  rejected (so auth is enforced), the rule cancels A's task as the wrong principal
  B. A **confirmed** finding is raised only when B's cancel succeeds and a
  read-back as owner A shows the task is now `canceled`.

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
definitive confirmation is an unauthenticated `message/send` that returns a task
result (the created task is then read back unauthenticated to corroborate). A
**confirmed** finding is raised only on a positive result envelope - never on an
ambiguous application error - so a server that answers the unauthenticated request
with HTTP 401/403 produces no finding.

This complements `a2a-task-idor-001`, which keys off whether anonymous creation is
rejected and **suppresses** its finding when the server enforces no authentication
at all - so a wide-open agent goes unflagged there. This rule flags exactly that
case, but only when the card promised authentication, making it an attributable
contract violation (CWE-287 / CWE-306). It is distinct from `a2a-extcard-unauth-001`
(the extended-card endpoint) and `a2a-card-trust-001` / `a2a-jws-algconf-001` (card
signatures).

---

### a2a-task-enumeration-001

**ListTasks Enumerates Another Principal's Tasks** | Severity: High | CWE-639 / CWE-200

Tests whether one authenticated principal can enumerate another's tasks through
`ListTasks`. The specification requires the opposite twice: section 3.1.4, on
`ListTasks` itself, states that "Implementations **MUST** implement appropriate
authorization scoping to ensure clients can only access authorized tasks", and section
13.1 that "Servers **MUST** return only tasks visible to the authenticated client".

Enumeration is worse than reading a task by id, because it needs no prior knowledge.
One valid credential yields every task identifier on the server, and those identifiers
are what the per-task read, cancel and push-notification-config surfaces take as input.

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
2. Control: A lists its own tasks and must see the task it just created. No list method
   at all (`-32601` on every spelling) is **clean**, the surface being absent. A refused
   listing, or one that omits the owner's own task, is **not tested**: B seeing nothing
   would prove nothing.
3. Control: an **unauthenticated** `ListTasks`. If it returns A's task, the server
   enforces no authorization on this surface at all, which is `a2a-task-idor-001`'s
   finding; reporting it here too would count one defect twice.
4. Principal B lists. A's task id appearing in B's response is the **confirmed**
   finding.

Identifiers are compared, never key names, and history is deliberately not requested
(`historyLength` 0): the failure is that the identifiers came back, and pulling another
tenant's conversation content to prove it would be gratuitous. `pageSize` is set high
so a scoped server has no pagination excuse for omitting a task.

Currency: `ListTasks` is a v1.0 JSON-RPC method. v0.3 defines `tasks/get`,
`tasks/cancel`, `tasks/resubscribe` and the push-notification-config methods, and no
list method, so a v0.3-only agent answers `-32601` and this reports not applicable. The
v0.3 REST binding's list path is covered anonymously by `a2a-task-idor-001`; the
authenticated case on that binding is not probed, because its prefix belongs to the
deployment and guessing it is how earlier rules came to post at paths that never
existed.
