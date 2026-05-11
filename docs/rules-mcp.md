# MCP Attack Rules

Batesian ships **17 rules** targeting the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).
All rules are active -- they send crafted payloads and evaluate the server's response rather than
passively observing what the endpoint exposes.

| Rule ID | Attack | Severity | CWE |
|---|---|:---:|---|
| `mcp-oauth-dcr-001` | [OAuth DCR Scope Escalation](#mcp-oauth-dcr-001) | High | CWE-284 |
| `mcp-tool-poison-001` | [Tool Description Poisoning / Rug Pull](#mcp-tool-poison-001) | High | CWE-494 |
| `mcp-resources-unauth-001` | [Unauthenticated Resource Read](#mcp-resources-unauth-001) | Critical | CWE-862 |
| `mcp-sampling-inject-001` | [Sampling Capability Injection Surface](#mcp-sampling-inject-001) | High | CWE-20 |
| `mcp-token-replay-001` | [OAuth Token Audience Validation Bypass](#mcp-token-replay-001) | High | CWE-294 |
| `mcp-oauth-audience-002` | [OAuth Audience Matching Bug Probes](#mcp-oauth-audience-002) | High | CWE-863 |
| `mcp-init-downgrade-001` | [Protocol Version Downgrade Auth Bypass](#mcp-init-downgrade-001) | High | CWE-757 |
| `mcp-cors-wildcard-001` | [CORS Wildcard Origin with Credentials](#mcp-cors-wildcard-001) | High | CWE-942 |
| `mcp-prompt-unauth-001` | [Prompt Templates Without Authentication](#mcp-prompt-unauth-001) | Medium | CWE-862 |
| `mcp-context-flood-001` | [Context Window Flooding](#mcp-context-flood-001) | Medium | CWE-400 |
| `mcp-tool-namespace-001` | [Tool Name Collision Across Sessions](#mcp-tool-namespace-001) | High | CWE-20 |
| `mcp-sse-hijack-001` | [Unauthenticated SSE Stream](#mcp-sse-hijack-001) | High | CWE-862 |
| `mcp-init-instructions-inject-001` | [Server Instructions Prompt Injection](#mcp-init-instructions-inject-001) | High | CWE-20 |
| `mcp-ratelimit-absent-001` | [Missing Rate Limiting](#mcp-ratelimit-absent-001) | Medium | CWE-770 |
| `mcp-homoglyph-tool-001` | [Tool Name Unicode Homoglyph Attack](#mcp-homoglyph-tool-001) | Medium | CWE-20 |
| `mcp-injection-params-001` | [Tool Parameter Injection (SQL / Command / XSS)](#mcp-injection-params-001) | High | CWE-77 |
| `mcp-security-headers-001` | [Missing HTTP Security Headers](#mcp-security-headers-001) | Low | CWE-16 |

---

## Rule Details

### mcp-oauth-dcr-001

**OAuth DCR Scope Escalation** | Severity: High | CWE-284

Sends a dynamic client registration request to the OAuth server's DCR endpoint with an inflated
scope set and a hijacked redirect URI. A vulnerable server grants the requested scopes without
validating them against an allowlist, or accepts redirect URIs pointing to attacker-controlled
domains.

---

### mcp-tool-poison-001

**Tool Description Poisoning / Rug Pull Detection** | Severity: High | CWE-494

Fetches the tool list and checks each tool `description` and `inputSchema` for prompt injection
patterns (role overrides, ignore-previous-instructions payloads, hidden Markdown directives).
Also calls `tools/list` twice across independent sessions and flags any description change as a
rug pull indicator.

---

### mcp-resources-unauth-001

**Unauthenticated Resource Read** | Severity: Critical | CWE-862

Sends `resources/list` and `resources/read` without any credentials. A vulnerable server returns
resource contents -- which may include secrets, configuration, or internal data -- without
requiring authentication.

---

### mcp-sampling-inject-001

**Sampling Capability Injection Surface** | Severity: High | CWE-20

Inspects the server's `sampling` capability declaration and sends a crafted
`sampling/createMessage` request embedding prompt injection payloads in the message content. A
vulnerable server forwards the injected content to the downstream LLM without sanitization.

---

### mcp-token-replay-001

**OAuth Token Audience Validation Bypass** | Severity: High | CWE-294

Crafts a Bearer JWT with a mismatched `aud` claim (targeting a different service), a future
`nbf`, and an expired `exp`, then submits it to the MCP endpoint. A vulnerable server accepts
the token without validating audience, time bounds, or signature.

---

### mcp-oauth-audience-002

**OAuth Audience Matching Bug Probes** | Severity: High | CWE-863

Probes whether the server's `aud` matching logic is robust to common implementation bugs
(`Contains` / `HasPrefix` substring matching, case folding, URL canonicalization, array-shape
branch skip) once the operator's expected audience value is known. Three forged HS256 JWT
canaries are derived from the value supplied via `--audience-claim` (or auto-discovered via
RFC 9728 protected resource metadata) and submitted to the first responsive MCP endpoint.
Per-endpoint outcomes are coalesced into a single rule-level finding.

**Honest scope.** Because probes are forged HS256 self-signed tokens, acceptance indicates a
compound failure of signature validation **and** audience matching. Catching servers that
validate signatures correctly but still mis-handle `aud` (the Parse CVE-2026-30863 /
RFC 7523-bis class) requires a real validly-signed cross-resource token and is tracked as a
follow-up. If `mcp-token-replay-001` is already firing on this target, fix those findings
first; this rule's results will likely be subsumed.

---

### mcp-init-downgrade-001

**Protocol Version Downgrade Auth Bypass** | Severity: High | CWE-757

Initializes the MCP session negotiating the older protocol version `2024-11-05` instead of the
current spec version. A vulnerable server disables security controls (authentication requirements,
scope enforcement) when operating in compatibility mode.

---

### mcp-cors-wildcard-001

**CORS Wildcard Origin with Credentials** | Severity: High | CWE-942

Sends a preflight request with `Origin: https://attacker.example.com` and checks whether the
server returns both `Access-Control-Allow-Origin: *` and
`Access-Control-Allow-Credentials: true`. This combination allows cross-origin requests with
credentials from any domain, enabling CSRF against authenticated MCP endpoints.

---

### mcp-prompt-unauth-001

**Prompt Templates Without Authentication** | Severity: Medium | CWE-862

Sends `prompts/list` and `prompts/get` without credentials. A vulnerable server returns prompt
template definitions -- which may contain sensitive system instructions or internal context --
without requiring authentication.

---

### mcp-context-flood-001

**Context Window Flooding** | Severity: Medium | CWE-400

Sends `tools/call` requests with 1 MB and 5 MB argument payloads. A vulnerable server accepts
the oversized payloads without a 413 or similar rejection, leaving it open to context window
exhaustion attacks against downstream LLMs.

---

### mcp-tool-namespace-001

**Tool Name Collision Across Sessions** | Severity: High | CWE-20

Opens two independent MCP sessions and compares the tool lists returned by each. Any tool that
appears in one session but not the other -- or with a different description -- is flagged as a
namespace collision indicator and a rug pull precondition.

---

### mcp-sse-hijack-001

**Unauthenticated SSE Stream** | Severity: High | CWE-862

Connects to the MCP SSE endpoint (`/sse`, `/events`, `/stream`) without authentication. A
vulnerable server establishes the SSE stream without requiring credentials, allowing an attacker
to receive real-time server-push messages intended for authenticated clients.

---

### mcp-init-instructions-inject-001

**Server Instructions Prompt Injection** | Severity: High | CWE-20

Initializes an MCP session and inspects the `serverInfo.instructions` field returned by the
server. A vulnerable server embeds prompt injection payloads in the instructions block, which
are consumed by client-side LLMs during session setup.

---

### mcp-ratelimit-absent-001

**Missing Rate Limiting** | Severity: Medium | CWE-770

Sends 25 rapid `initialize` requests and checks whether any response carries HTTP 429 or a
`Retry-After` header. A server with no rate limiting accepts the burst without throttling,
leaving it open to resource exhaustion and credential-stuffing attacks.

---

### mcp-homoglyph-tool-001

**Tool Name Unicode Homoglyph Attack** | Severity: Medium | CWE-20

Sends a `tools/call` request substituting Unicode homoglyphs for characters in a legitimate
tool name (e.g., Cyrillic "a" for Latin "a"). A vulnerable server routes the call to the
matching tool without Unicode normalization, enabling tool invocation via visually identical but
semantically distinct identifiers.

---

### mcp-injection-params-001

**Tool Parameter Injection (SQL / Command / XSS)** | Severity: High | CWE-77

Calls each advertised tool with SQL injection, shell command injection, and script tag payloads
in string parameters. A vulnerable server reflects the injected content in its response (error
messages, output fields), indicating the parameters are passed to a backend without sanitization.

---

### mcp-security-headers-001

**Missing HTTP Security Headers** | Severity: Low | CWE-16

Checks MCP endpoints for the presence of `Strict-Transport-Security`, `X-Content-Type-Options`,
`X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, and `Permissions-Policy`. Absent
headers are reported as indicators.
