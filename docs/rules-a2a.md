# A2A Attack Rules

Batesian ships **14 rules** targeting the [Agent-to-Agent (A2A) protocol](https://google.github.io/A2A/).
Every rule is an active probe: it sends crafted protocol traffic and judges the
server's actual response. Rules are deliberately scoped to A2A-specific semantics
(agent cards, JWS card signatures, tasks/contexts, push notifications, peer
identity) rather than generic web hygiene.

Each finding carries a **confidence**:

- **confirmed** - the attack was demonstrably successful (e.g. the tampered value
  was read back, the forged token was accepted against a rejecting baseline).
- **indicator** - a suspicious posture was observed but exploitation could not be
  proven from the response alone; manual verification is recommended.

| Rule ID | Attack | Severity | Confidence | CWE |
|---|---|:---:|:---:|---|
| `a2a-extcard-unauth-001` | [Extended Agent Card Unauthenticated Disclosure](#a2a-extcard-unauth-001) | High | confirmed | CWE-862 |
| `a2a-push-ssrf-001` | [Push Notification SSRF](#a2a-push-ssrf-001) | High | confirmed | CWE-918 |
| `a2a-task-idor-001` | [Task IDOR via Unauthenticated tasks/get](#a2a-task-idor-001) | High | confirmed | CWE-639 |
| `a2a-session-smuggle-001` | [Agent Role Injection / Session Smuggling](#a2a-session-smuggle-001) | High | confirmed / indicator | CWE-384 |
| `a2a-wellknown-hostinject-001` | [Agent Card Host Header Injection](#a2a-wellknown-hostinject-001) | High / Medium | confirmed / indicator | CWE-601 |
| `a2a-jws-algconf-001` | [AgentCard JWS Algorithm Confusion](#a2a-jws-algconf-001) | Critical | indicator | CWE-327 |
| `a2a-peer-impersonation-001` | [Peer Agent Impersonation via Forged JWT](#a2a-peer-impersonation-001) | Critical | confirmed | CWE-290 |
| `a2a-artifact-tamper-001` | [Task Artifact Tampering via Task ID Reuse](#a2a-artifact-tamper-001) | High | confirmed / indicator | CWE-284 |
| `a2a-multitenant-isolation-001` | [Multi-Tenant Task Isolation Breach](#a2a-multitenant-isolation-001) | High | confirmed | CWE-639 |
| `a2a-delegation-integrity-001` | [Delegation Chain-of-Custody Break](#a2a-delegation-integrity-001) | High | confirmed | CWE-863 |
| `a2a-context-fixation-001` | [Context ID Fixation](#a2a-context-fixation-001) | High | confirmed | CWE-384 |
| `a2a-card-trust-001` | [Agent Card Trust Durability](#a2a-card-trust-001) | High / Medium | confirmed / indicator | CWE-345 |
| `a2a-extension-downgrade-001` | [Required-Extension Downgrade / Fail-Open](#a2a-extension-downgrade-001) | High | confirmed | CWE-636 |
| `a2a-push-binding-001` | [Push/Webhook Control-Plane Not Bound to Task Owner](#a2a-push-binding-001) | High | confirmed | CWE-639 |

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

Sends a `message/send` request with `role: agent` - a role the spec reserves for
server-originated messages - and then **reads the task history back** to confirm
whether the injection actually landed. Only when the marker is stored as an
agent-role turn is a **confirmed** exploit reported. If the server rejects the
role (`-32602`) or normalizes it to `user`, no finding is raised; if acceptance
cannot be verified from retrievable history, it is downgraded to an **indicator**.

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
any `*.url`/`*.uri`, or any value that is itself a URL) is **high / confirmed** -
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

A **chained CONSUMER** rule (roadmap #24) - the first rule that consumes another
rule's blackboard output. It declares `Requires(task-id)`, so the engine runs it
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

The A2A half of the session/task-ID fixation concern (roadmap #27; the MCP half
is `mcp-session-fixation-001`). A2A groups a conversation by `contextId`; the
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
  reported **confirmed (high)**. If both are signed but their `url` differs,
  reported as an **indicator (medium)** (routing ambiguity).
- **Stale-cache trust.** The card response's `Cache-Control` is parsed. A long
  `max-age` (>= 1h) or `immutable` without `no-cache`/`must-revalidate` keeps the
  trust anchor cached after key rotation or compromise (**indicator, medium**); a
  missing `Cache-Control` is a weaker heuristic-caching **indicator (low)**.
  `no-store`/`no-cache`/`must-revalidate`/`max-age=0` produce no finding.
- **Signature freshness.** When the card carries signatures, each protected
  header is decoded: no `exp` means the signature never expires (**indicator,
  medium**); an `exp` already in the past that is still served is a **confirmed**
  stale signature.

---

### a2a-extension-downgrade-001

**Required-Extension Downgrade / Fail-Open** | Severity: High | CWE-636

A2A agent cards advertise protocol extensions under `capabilities.extensions[]`,
each with a `uri` and a `required` flag; clients activate one via the
`X-A2A-Extensions` request header. A required extension is a capability the
server states clients MUST activate, so the server must reject requests that do
not. This rule is card-driven and confirms a fail-open downgrade only with a
control/test pair: it reads the card, and for each `required: true` extension it
(1) sends a `SendMessage` that **activates** the extension (control - must be
accepted or the rule can't test), then (2) sends an identical `SendMessage` with
the `X-A2A-Extensions` header **omitted**. A **confirmed** finding is raised only
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

