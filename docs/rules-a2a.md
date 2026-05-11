# A2A Attack Rules

Batesian ships **18 rules** targeting the [Agent-to-Agent (A2A) protocol](https://google.github.io/A2A/).
All rules are active -- they send crafted payloads and evaluate the server's response rather than
passively observing what the endpoint exposes.

| Rule ID | Attack | Severity | CWE |
|---|---|:---:|---|
| `a2a-push-ssrf-001` | [Push Notification SSRF](#a2a-push-ssrf-001) | High | CWE-918 |
| `a2a-extcard-unauth-001` | [Extended Agent Card Unauthenticated Disclosure](#a2a-extcard-unauth-001) | High | CWE-862 |
| `a2a-jws-algconf-001` | [JWS Algorithm Confusion / Signature Bypass](#a2a-jws-algconf-001) | Critical | CWE-327 |
| `a2a-session-smuggle-001` | [Agent Role Injection / Session Smuggling](#a2a-session-smuggle-001) | High | CWE-384 |
| `a2a-task-idor-001` | [Task IDOR via Unauthenticated tasks/get](#a2a-task-idor-001) | High | CWE-639 |
| `a2a-context-orphan-001` | [Cross-Session Context Injection](#a2a-context-orphan-001) | High | CWE-200 |
| `a2a-json-rpc-fuzz-001` | [JSON-RPC Mutation Fuzzing](#a2a-json-rpc-fuzz-001) | Medium | CWE-20 |
| `a2a-peer-impersonation-001` | [Peer Agent Impersonation via Forged JWT](#a2a-peer-impersonation-001) | Critical | CWE-290 |
| `a2a-delegation-escalation-001` | [Privilege Escalation via Delegation Metadata](#a2a-delegation-escalation-001) | High | CWE-269 |
| `a2a-wellknown-hostinject-001` | [Agent Card Host Header Injection](#a2a-wellknown-hostinject-001) | High | CWE-601 |
| `a2a-artifact-tamper-001` | [Task Artifact Tampering via Task ID Reuse](#a2a-artifact-tamper-001) | High | CWE-284 |
| `a2a-skill-poison-001` | [Skill Description Injection](#a2a-skill-poison-001) | High | CWE-20 |
| `a2a-url-mismatch-001` | [Agent Card URL Disagrees with Origin Domain](#a2a-url-mismatch-001) | Medium | CWE-345 |
| `a2a-tls-downgrade-001` | [TLS Downgrade / Plain HTTP Acceptance](#a2a-tls-downgrade-001) | High | CWE-319 |
| `a2a-capability-inflation-001` | [Undeclared Capability Acceptance](#a2a-capability-inflation-001) | High | CWE-284 |
| `a2a-security-headers-001` | [Missing HTTP Security Headers](#a2a-security-headers-001) | Low | CWE-16 |
| `a2a-registry-poison-001` | [Unauthenticated Agent Registry Poisoning](#a2a-registry-poison-001) | High | CWE-290 |
| `a2a-circular-delegation-001` | [Circular Task Delegation](#a2a-circular-delegation-001) | Medium | CWE-674 |

---

## Rule Details

### a2a-push-ssrf-001

**Push Notification SSRF** | Severity: High | CWE-918

Registers an attacker-controlled URL as a push notification callback, then submits a task. A
vulnerable server makes an outbound HTTP request to the callback on task completion, confirming
blind SSRF. This is a confirmed unfixed issue in the reference `a2a-python` SDK as of April 2026.

---

### a2a-extcard-unauth-001

**Extended Agent Card Unauthenticated Disclosure** | Severity: High | CWE-862

Fetches the extended agent card endpoints (`/extendedAgentCard`,
`/agent/authenticatedExtendedCard`) without credentials. A vulnerable server returns privileged
capability information -- OAuth scopes, internal skill metadata -- that should require
authentication.

---

### a2a-jws-algconf-001

**JWS Algorithm Confusion / Signature Bypass** | Severity: Critical | CWE-327

Crafts JWS tokens with `"alg":"none"` and with an RS256-to-HS256 downgrade (signing an RS256
key with HMAC-SHA256). A vulnerable server accepts unsigned or trivially forged tokens, allowing
identity spoofing without knowledge of the private key.

---

### a2a-session-smuggle-001

**Agent Role Injection / Session Smuggling** | Severity: High | CWE-384

Sends a `tasks/send` request with `role: agent` in the message parts from an unauthenticated
client. A vulnerable server accepts the elevated role claim, allowing covert instruction
injection into a session under an agent identity.

---

### a2a-task-idor-001

**Task IDOR via Unauthenticated tasks/get** | Severity: High | CWE-639

Submits a task from one session, then attempts to retrieve it via `tasks/get` from a different,
unauthenticated session using the known task ID. A vulnerable server returns the task state and
artifacts to any caller who knows the ID.

---

### a2a-context-orphan-001

**Cross-Session Context Injection via contextId Reuse** | Severity: High | CWE-200

Creates a task with a known `contextId`, then injects a new task into the same context from a
separate unauthenticated session. A vulnerable server processes the injected task within the
original session's context, enabling cross-session data leakage or instruction smuggling.

---

### a2a-json-rpc-fuzz-001

**JSON-RPC Mutation Fuzzing** | Severity: Medium | CWE-20

Sends a series of malformed JSON-RPC payloads: missing `method`, wrong `id` type, extra unknown
fields, deeply nested objects. A vulnerable server responds with 500 errors or stack traces
rather than spec-compliant error responses.

---

### a2a-peer-impersonation-001

**Peer Agent Impersonation via Forged JWT** | Severity: Critical | CWE-290

Crafts a Bearer JWT claiming to be a trusted peer agent identity and submits it to the A2A
endpoint without a valid signature. A vulnerable server accepts the request without verifying the
token's signature or origin, allowing full peer identity spoofing.

---

### a2a-delegation-escalation-001

**Privilege Escalation via Delegation Metadata Injection** | Severity: High | CWE-269

Injects elevated permission metadata into the `configuration` block of a `tasks/send` request.
A vulnerable server echoes back or acts on the injected delegation metadata without validating
that the caller is authorized to claim those permissions.

---

### a2a-wellknown-hostinject-001

**Agent Card Host Header Injection** | Severity: High | CWE-601

Requests the agent card at `/.well-known/agent-card.json` with a crafted `Host`,
`X-Forwarded-Host`, or `X-Original-Host` header. A vulnerable server reflects the attacker-
controlled domain in the card's `url` field, enabling cache poisoning or open redirect via the
agent directory.

---

### a2a-artifact-tamper-001

**Task Artifact Tampering via Task ID Reuse** | Severity: High | CWE-284

Submits a task, captures its ID after completion, then resubmits the same task ID with different
content. A vulnerable server accepts the resubmission without enforcing immutability on completed
task artifacts.

---

### a2a-skill-poison-001

**Skill Description Injection** | Severity: High | CWE-20

Retrieves the agent card and checks skill `description` and `examples` fields for prompt
injection patterns -- phrases like "ignore previous instructions", system role overrides, and
hidden Markdown directives. A vulnerable server serves agent cards that could poison downstream
LLM agents consuming the metadata.

---

### a2a-url-mismatch-001

**Agent Card URL Disagrees with Origin Domain** | Severity: Medium | CWE-345

Compares the `url` field in the agent card against the domain the card was served from. A
mismatch is an indicator of a misconfigured or spoofed deployment -- the card may have been
copied or proxied without updating its identity fields.

---

### a2a-tls-downgrade-001

**TLS Downgrade / Plain HTTP Acceptance** | Severity: High | CWE-319

Sends the agent card fetch and JSON-RPC request over plain `http://`. A vulnerable server
responds successfully over cleartext rather than redirecting to HTTPS, exposing all traffic to
interception.

---

### a2a-capability-inflation-001

**Undeclared Capability Acceptance** | Severity: High | CWE-284

Sends a `tasks/send` request claiming elevated permissions that were never declared in the agent
card's capability set. A vulnerable server processes the request without rejecting the
undeclared capability claim.

---

### a2a-security-headers-001

**Missing HTTP Security Headers** | Severity: Low | CWE-16

Checks A2A endpoints for the presence of `Strict-Transport-Security`, `X-Content-Type-Options`,
`X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, and `Permissions-Policy`. Absent
headers are reported as indicators.

---

### a2a-registry-poison-001

**Unauthenticated Agent Registry Poisoning** | Severity: High | CWE-290

Sends an unauthenticated POST to common agent registry endpoints attempting to register or
overwrite an agent card entry. A vulnerable registry accepts the registration without
authentication, allowing an attacker to inject malicious agent identities.

---

### a2a-circular-delegation-001

**Circular Task Delegation** | Severity: Medium | CWE-674

Submits a `tasks/send` request that includes a 10-hop delegation chain in its metadata. A
vulnerable server processes the request without enforcing a delegation depth limit, opening the
door to unbounded recursive delegation loops.
