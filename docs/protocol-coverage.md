# Protocol and advisory coverage

This page records what the live compatibility gates and endpoint rules actually
exercise. The advisory matrix was reviewed on 2026-10-28; the modern protocol
sections were updated on 2026-10-29. A rule finding describes observed behavior
on the scanned surface; it does not establish that a particular package or CVE
is present.

## Protocol compatibility gates

| Protocol | Reference target | CI exercise | Limit |
|---|---|---|---|
| [A2A 1.0.1](https://a2a-protocol.org/v1.0.1/specification/) | Current [A2A Python SDK 1.x](https://github.com/a2aproject/a2a-python/releases) | Card discovery; JSON-RPC `SendMessage`/`GetTask`; HTTP+JSON `message:send`/`tasks/{id}`; confirmed `a2a-session-smuggle-001` on JSON-RPC | The SDK target is not a secured deployment. The rule check is on JSON-RPC only. |
| [A2A 1.0.1](https://a2a-protocol.org/v1.0.1/specification/) | Bundled vulnerable and bound push fixtures | JSON-RPC and HTTP+JSON subscription scope controls | These fixtures implement only the routes needed by the rule. |
| [A2A 0.3.0](https://a2a-protocol.org/v0.3.0/specification/) | Bundled JSON-RPC fixtures and Go test servers | Legacy method names, card shapes, and security rule controls in Go tests | There is no current official 0.3 SDK target in CI. |
| [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) | Current [MCP Python SDK 2.x](https://github.com/modelcontextprotocol/python-sdk/releases) | `server/discover`, initialization compatibility, session opening, and a clean two-principal cache-scope scan on PRs and weekly | The SDK server returns the same data to both test principals; the vulnerable cache-scope control is a Go fixture. |
| [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) | Same dual-era SDK target and bundled fixtures | Legacy `initialize` and session opening, plus rule controls | No official SDK in every supported language is exercised. |

The SDK dependencies intentionally float within a major version. These gates
catch changes in the current Python implementations; the fixture and Go tests
pin expected protocol behavior when a dependency changes.

## Modern MCP state and cache checks

| Surface | Endpoint test | Current decision |
|---|---|---|
| [Public cache scope](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching) | Compare stable results for two principals on `server/discover` and read-only list methods. | `mcp-cache-scope-001` reports different principal results with positive public TTL as an indicator. It does not test `resources/read` or client cache behavior. |
| [Subscriptions](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions) | A cross-principal notification leak needs a resource both identities can address and a safe way to trigger an update. | No generic rule yet. An acknowledgment alone cannot prove that another principal received an event, and routine scans should not mutate arbitrary resources to create one. |
| [Multi round-trip state](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr) | A state-integrity failure needs a safe `input_required` flow and an observable change in authorization or resource access after a modified `requestState`. | No generic rule yet. Accepting an altered opaque state is not itself an exploit; the specification allows unprotected state when tampering can only fail the request. |

## MCP compatibility notes

The modern request builder mirrors `Mcp-Method` and named subjects into
`Mcp-Name`, including task IDs. Anonymous tool and prompt list rules probe a
modern server even when discovery omits the matching capability. Tasks and
annotated-header probes follow up to ten `tools/list` pages and mark broken
pagination not tested.

OAuth authorization-server metadata is accepted only when its `issuer` matches
the issuer used for the well-known URL. The DCR redirect probe includes an
S256 PKCE challenge but does not exchange an authorization code. Legacy sessions
opened through shared wire discovery are closed with DELETE when the server
issues a session ID; servers may decline cleanup with HTTP 405.

## Advisory-to-rule matrix

The table separates an **endpoint behavior** that a bounded HTTP scan may see
from a **component or deployment condition** that needs package inventory,
client instrumentation, or host metrics. An existing rule may test a related
failure mode without establishing the cited advisory.

| Advisory | Observable from an MCP endpoint? | Batesian coverage | Remaining verification |
|---|---|---|---|
| [Python SDK session retention, GHSA-84m7-p3x7-pcfv](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-84m7-p3x7-pcfv) | Session creation is observable; unbounded retention and memory growth are not established by a short scan. | None specific. | Check installed SDK version, stateful mode, session limits, and process memory over time. |
| [TypeScript SDK response crossover, GHSA-jm63-cq47-j5jp](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-jm63-cq47-j5jp) | Potentially, with two isolated clients using colliding JSON-RPC IDs. | No direct test. `mcp-task-idor-001` checks durable task ownership on the legacy wire, a different boundary. | Inspect transport/server instance lifetime and SDK version; a dedicated concurrency fixture is needed before claiming endpoint detection. |
| [server-everything environment disclosure, GHSA-mvf5-2qqv-rg3c](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-mvf5-2qqv-rg3c) | Open tool listing, authentication, and Origin responses are observable. Environment exfiltration requires invoking `get-env`. | `mcp-tools-unauth-001` and `mcp-dns-rebind-origin-001` may report contributing behavior; neither proves this advisory. | Verify package version, network binding, CORS, and whether `get-env` exposes secrets. Do not invoke it during a routine scan. |
| [server-filesystem path mismatch, GHSA-7rgq-gccq-qphx](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-7rgq-gccq-qphx) | Potentially, with a configured allowed directory and safe path oracle. | `mcp-tool-param-traversal-001` tests other traversal encodings on approved read-only tools; it does not send the advisory's trailing quote/space payload. | Check package version and path validation in a controlled deployment. A new safe fixture and oracle would be needed for this variant. |
| [mcp-server-fetch IDNA SSRF, GHSA-v38p-wf49-hx2j](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-v38p-wf49-hx2j) | A controlled outbound callback may prove a fetch. It cannot by itself prove access to a private address. | No specific rule. `mcp-oauth-metadata-ssrf-001` tests OAuth registration metadata, not the `fetch` tool. | Verify package version and DNS behavior in an isolated network. |
| [mcp-server-fetch robots redirect bypass, GHSA-3jqg-r5pp-rmp2](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-3jqg-r5pp-rmp2) | Potentially, with a controlled redirect and robots policy. | No specific rule. | Verify package version and redirect policy with a controlled server. |
| [Rust SDK OAuth resource metadata fetch, GHSA-c9xm-49cp-xcr9](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-c9xm-49cp-xcr9) | The malicious metadata is served by the endpoint, but the vulnerable fetch occurs in a client. | No client-side test. `mcp-oauth-metadata-ssrf-001` probes a server's DCR handling, a different direction of trust. | Inspect the client SDK version or run a client-side test. |

`mcp-vulnerable-version-001` matches a closed set of self-reported component
names and versions documented in [the MCP rules](rules-mcp.md#mcp-vulnerable-version-001).
It does not currently identify the advisories above. Even for listed components,
its result is an indicator, not exploit confirmation.

**Log-only evidence.** The current [MCP Python SDK logging guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/handlers/logging.md)
uses process logging on stderr; those records do not appear in an endpoint
response. Batesian cannot verify claims that depend on server audit logs or
long-term telemetry from HTTP alone. `mcp-log-optin-001` tests protocol log
notifications on the wire, not a server's log sink. The official
[A2A Python](https://github.com/a2aproject/a2a-python/security/advisories)
and [A2A JavaScript](https://github.com/a2aproject/a2a-js/security/advisories)
repositories listed no published advisories at the review date; their endpoint
misconfiguration checks remain in [the A2A rules](rules-a2a.md).
