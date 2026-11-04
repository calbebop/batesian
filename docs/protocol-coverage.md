# Protocol and advisory coverage

This page records what the live compatibility gates and endpoint rules actually
exercise. The advisory matrix was reviewed on 2026-11-04; the modern protocol
sections were updated on 2026-11-04. A rule finding describes observed behavior
on the scanned surface; it does not establish that a particular package or CVE
is present.

## Protocol compatibility gates

| Protocol | Reference target | CI exercise | Limit |
|---|---|---|---|
| [A2A 1.0.1](https://a2a-protocol.org/v1.0.1/specification/) | Current [A2A Python SDK 1.x](https://github.com/a2aproject/a2a-python/releases) | Card discovery; JSON-RPC `SendMessage`/`GetTask`; HTTP+JSON `message:send`/`tasks/{id}`; confirmed `a2a-session-smuggle-001` on JSON-RPC | The SDK target is not a secured deployment. The rule check is on JSON-RPC only. |
| [A2A 1.0.1](https://a2a-protocol.org/v1.0.1/specification/) | Bundled dual-binding tenant fixture | `a2a-multitenant-isolation-001` reads owner-created tasks across advertised JSON-RPC and HTTP+JSON in both directions, with protected, public, and malformed controls. | The fixture exercises the authorization oracle, not an official SDK deployment. Tenant-scoped interface pairs are not covered by this cross-binding check. |
| [A2A 1.0.1](https://a2a-protocol.org/v1.0.1/specification/) | Pinned [A2A Go SDK v2.7.0](https://github.com/a2aproject/a2a-go/releases/tag/v2.7.0) gRPC handler | `a2a-grpc-task-access-001` against protected, vulnerable, public, malformed, and unsupported task-read controls in Go tests | Opt-in v1.0 `SendMessage`/`GetTask` only. No streaming, v0.3 gRPC, or tenant-scoped interfaces. |
| [A2A 1.0.1](https://a2a-protocol.org/v1.0.1/specification/) | Bundled vulnerable and bound push fixtures | JSON-RPC and HTTP+JSON subscription scope controls | These fixtures implement only the routes needed by the rule. |
| [A2A 0.3.0](https://a2a-protocol.org/v0.3.0/specification/) | Bundled JSON-RPC fixtures and Go test servers | Legacy method names, card shapes, and security rule controls in Go tests | There is no current official 0.3 SDK target in CI. |
| [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) | Current [MCP Python SDK 2.x](https://github.com/modelcontextprotocol/python-sdk/releases) | `server/discover`, initialization compatibility, session opening, and a clean two-principal cache-scope scan on PRs and weekly | The SDK server returns the same data to both test principals; the vulnerable cache-scope control is a Go fixture. |
| [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) | Current [MCP TypeScript server SDK 2.x](https://github.com/modelcontextprotocol/typescript-sdk/tree/main/packages/server) | `server/discover`, dual-era session opening, and a named tool call through Batesian's modern request headers on PRs and weekly | The fixture has no authentication or tenant policy; it checks protocol compatibility, not authorization findings. |
| [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) | Both dual-era SDK targets and bundled fixtures | Legacy `initialize` and session opening, plus rule controls | No official SDK in every supported language is exercised. |

The 2024-11-05 HTTP+SSE transport is not covered. It uses a long-lived GET stream
and a separate POST endpoint rather than the Streamable HTTP request path used by
Batesian. See the [official Go SDK transport guide](https://go.sdk.modelcontextprotocol.io/protocol/).

The Python and TypeScript SDK dependencies intentionally float within a major
version. These gates catch changes in the current implementations; the fixtures
and Go tests pin expected protocol behavior when a dependency changes.

## A2A gRPC assessment

[A2A 1.0.1](https://a2a-protocol.org/v1.0.1/specification/#grpc-protocol-binding)
defines gRPC using protobuf over HTTP/2. The
[official TCK](https://github.com/a2aproject/a2a-tck#transports) tests gRPC,
JSON-RPC, and HTTP+JSON conformance. Batesian's opt-in gRPC rule checks one
v1.0 `SendMessage`/`GetTask` authorization boundary with the official Go SDK
handler as its compatibility fixture. The configured endpoint must match a
card-advertised address, and plaintext is limited to loopback. The rule uses
per-call deadlines, bounded responses, and no streams.

Other A2A rules still use JSON-RPC and HTTP+JSON. gRPC task access is not broad
transport parity: v0.3, streaming, push, tenant-scoped interfaces, and path-based
gRPC proxies remain untested. The TCK validates protocol behavior but does not
establish a security finding. A gRPC-only card must not make HTTP rules look
clean when their bindings are unavailable.

## Modern MCP state and cache checks

| Surface | Endpoint test | Current decision |
|---|---|---|
| [Public cache scope](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching) | Compare stable result content and metadata for two principals on `server/discover`, up to three comparable list pages, and up to five shared resources sampled across three list pages per principal. | `mcp-cache-scope-001` reports different principal results with positive public TTL or a cache-scope change across list pages as indicators. Later list pages require a common cursor; the rule does not test client cache behavior. |
| [MCP Skills](https://skills.extensions.modelcontextprotocol.io/specification/beta/skills) and [MCP Apps](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx) | On the modern wire, compare sampled Skills manifests with SKILL.md reads and Apps tool UI references with resource reads. | `mcp-extension-consistency-001` reports stable content or resource-format mismatches as indicators. It does not load skills, execute tools, render Apps, or test host sandbox and approval behavior. |
| [Subscriptions](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions) | With an operator-configured disposable resource and update tool, compare an explicit caller read denial against owner and caller update events, changed owner content, and correlated subscription IDs. | `mcp-subscription-scope-001` reports a delivered cross-principal update as an indicator. It does not run without the configured trigger, and an acknowledgment alone never proves a leak. |
| [Multi round-trip state](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr) | Compare a denied `resources/read` baseline with a retry using another principal's state, then verify content against an owner retry. | `mcp-mrtr-state-001` samples up to five resources across three list pages. It does not answer input requests or test arbitrary state tampering and expiry. A handoff is an indicator unless the operator declares an expected denial. |
| [Cross-client response isolation](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-jm63-cq47-j5jp) | Send concurrent resource reads from two isolated clients with colliding JSON-RPC IDs after stable and denied baseline controls. | `mcp-response-crossover-001` confirms only an observed cross-client response. It cannot identify an SDK version or rule out a timing-dependent race after bounded attempts. |

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
issues a session ID. `probe` also closes its authenticated and anonymous legacy
sessions, including after inventory errors. Servers may decline cleanup with
HTTP 405; stateless modern requests need no session cleanup.

Legacy `resources/read` may use `-32002` for a missing resource. The 2026-07-28
revision uses `-32602`. Some SDKs also use `-32001` for a missing session.
Batesian requires an explicit authorization message before treating either code
as a denial.

## Advisory-to-rule matrix

The tables separate an **endpoint behavior** that a bounded scan may see
from a **component or deployment condition** that needs package inventory,
client instrumentation, or host metrics. An existing rule may test a related
failure mode without establishing the cited advisory.

### A2A Java SDK

As of 2026-11-04, the official Java SDK listed five published advisories. Its
package version and authorization wiring are not exposed reliably by an Agent
Card, so Batesian does not identify an affected Java release from endpoint
behavior alone.

| Advisory | Endpoint visibility | Batesian coverage | Remaining verification |
|---|---|---|---|
| [Fail-open task authorization, GHSA-qw47-mcm5-934w](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-qw47-mcm5-934w) | Another caller may read a task, but an endpoint scan cannot establish the SDK version, handler wiring, or intended sharing policy. | `a2a-multitenant-isolation-001` requires a private-task control. `a2a-task-idor-001` requires anonymous creation to be denied. Both stay silent on a fully open server. `a2a-card-security-unenforced-001` requires a card that promises authentication. The opt-in `a2a-grpc-task-access-001` checks one gRPC task-read boundary. None identifies this advisory. | Check the installed `server-common` version and `TaskAuthorizationProvider` wiring. Upgrade releases through 1.2.0.Final to 1.3.0.Final or later, and verify that production has an ownership policy rather than `a2a.authorization.required=false`. |
| [Push callback SSRF, GHSA-q78c-5jjq-57g8](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-q78c-5jjq-57g8) | A controlled callback can show delivery to the scanner's private listener. It cannot prove access to other internal addresses or redirect and DNS-rebinding bypasses. | `a2a-push-ssrf-001` reports observed private callback delivery as an indicator, not a confirmed exploit or SDK fingerprint. No callback is inconclusive when the listener is unreachable or the task finishes before delivery. | Check the installed `server-common` version, upgrade releases through 1.2.0.Final to 1.3.0.Final or later, and verify push destination and egress policy for resolved addresses and redirects. |
| [Client API-key redirect leak, GHSA-9rhm-2h4x-jwmx](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-9rhm-2h4x-jwmx) | A server can advertise a custom credential header and redirect, but the credential leak occurs in a Java client following that redirect. | No client-side test. Agent Card inspection does not establish how a client handles credentials. | Check the Java client version and redirect handling; releases through 1.2.0.Final are affected and 1.3.0.Final is patched. Use synthetic credentials in an isolated client test. |
| [REST push credentials in logs, GHSA-x32g-jvvm-4725](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-x32g-jvvm-4725) | A malformed push-config request may return an error, but the alleged exposure is in server logs, not the response. | No log-side test. Batesian does not submit credentials to provoke a logging failure. | Check the installed `transport-rest` version and log handling; releases through 1.2.0.Final are affected and 1.3.0.Final is patched. Verify with synthetic values and authorized log access. |
| [Android POST redirect leak, GHSA-4fpj-g9jf-9rgg](https://github.com/a2aproject/a2a-java/security/advisories/GHSA-4fpj-g9jf-9rgg) | The leak occurs when the Android client follows a cross-authority redirect while sending a custom auth header. | No Android client-side test. | Check `http-client-android` independently: 1.3.0.Final and 1.3.1.Final are affected, and 1.3.2.Final is patched. Test redirects with synthetic credentials if needed. |

### MCP SDKs and reference servers

| Advisory | Observable from an MCP endpoint? | Batesian coverage | Remaining verification |
|---|---|---|---|
| [Python SDK session retention, GHSA-84m7-p3x7-pcfv](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-84m7-p3x7-pcfv) | Session creation is observable; unbounded retention and memory growth are not established by a short scan. | None specific. | Check installed SDK version, stateful mode, session limits, and process memory over time. |
| [TypeScript SDK response crossover, GHSA-jm63-cq47-j5jp](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-jm63-cq47-j5jp) | Potentially, with two isolated clients using colliding JSON-RPC IDs. | `mcp-response-crossover-001` confirms an observed cross-client resource response with a denied baseline and stable controls. It does not identify the package or version. | Inspect transport/server instance lifetime and SDK version; absence of a finding does not rule out the race. |
| [server-everything environment disclosure, GHSA-mvf5-2qqv-rg3c](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-mvf5-2qqv-rg3c) | Open tool listing, authentication, and Origin responses are observable. Environment exfiltration requires invoking `get-env`. | `mcp-tools-unauth-001` and `mcp-dns-rebind-origin-001` may report contributing behavior; neither proves this advisory. | Verify package version, network binding, CORS, and whether `get-env` exposes secrets. Do not invoke it during a routine scan. |
| [mcp-server-git repository confinement bypass, GHSA-w766-5x43-whvw](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-w766-5x43-whvw) | A prepared nested `.git` indirection could expose an outside repository, but creating it changes target state. | `mcp-vulnerable-version-001` flags self-reported `mcp-git` versions from 2026.10.10 through 2026.10.27. It does not invoke Git tools or verify `--repository` confinement. | Verify the installed `mcp-server-git` version and whether an attacker can place a nested `.git` file inside the allowed repository. |
| [server-filesystem path mismatch, GHSA-7rgq-gccq-qphx](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-7rgq-gccq-qphx) | Yes, with a configured allowed directory and approved metadata tool. | `mcp-filesystem-suffix-001` compares missing-path and denied-path controls with trailing quote and space siblings. `mcp-vulnerable-version-001` flags affected self-reported 1.x versions; earlier builds report a static server version. Neither identifies the installed package independently. | Check the installed package version and ensure the suffixed siblings are nonexistent in a controlled deployment. |
| [server-filesystem symlink metadata disclosure, GHSA-hhwq-wxfx-cj7g](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-hhwq-wxfx-cj7g) | Yes, with a disposable symlink and outside file of known size. | `mcp-filesystem-symlink-001` compares denied direct metadata controls with the link's directory listing. `mcp-vulnerable-version-001` separately flags affected self-reported 1.x versions. Neither identifies the installed package independently. | Verify the installed package version and run the opt-in probe with an unchanged fixture. |
| [server-filesystem case-variant symlink write, GHSA-4gxg-m5jx-9j57](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-4gxg-m5jx-9j57) | Exploitation requires a case-insensitive filesystem, a prepared symlink, and a write or create operation. | `mcp-vulnerable-version-001` flags self-reported 1.x and 2.0.0 versions. The read-only symlink metadata rule does not test this write escape. | Verify the installed package version, filesystem case behavior, and allowed-directory layout. Test writes only in an isolated disposable fixture. |
| [server-filesystem parent-directory race, GHSA-53mr-w429-c597](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-53mr-w429-c597) | Exploitation requires a competing local actor to replace a validated parent directory before a write. | `mcp-vulnerable-version-001` flags self-reported 1.x and 2.0.0 versions. A bounded remote scan cannot prove the race is reachable. | Verify the installed package version and local filesystem threat model. Do not run a race exploit in routine scans. |
| [mcp-server-fetch IDNA SSRF, GHSA-v38p-wf49-hx2j](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-v38p-wf49-hx2j) | A controlled outbound callback may prove a fetch. It cannot by itself prove access to a private address. | `mcp-vulnerable-version-001` flags affected self-reported `mcp-fetch` versions. It does not invoke the `fetch` tool or establish SSRF. | Verify the installed package version and DNS behavior in an isolated network. |
| [mcp-server-fetch robots redirect bypass, GHSA-3jqg-r5pp-rmp2](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-3jqg-r5pp-rmp2) | Potentially, with a controlled redirect and robots policy. | `mcp-vulnerable-version-001` flags affected self-reported `mcp-fetch` versions from 2026.10.10 onward. Older builds may report an SDK version instead. It does not test redirect enforcement. | Verify the installed package version and redirect policy with a controlled server. |
| [mcp-server-fetch NAT64 SSRF, GHSA-66qx-2266-pmj6](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-66qx-2266-pmj6) | Potentially, on a network with NAT64 egress. | `mcp-vulnerable-version-001` flags affected self-reported `mcp-fetch` versions. It does not test NAT64 routing or invoke the `fetch` tool. | Verify the installed package version and network behavior in an isolated deployment. |
| [Rust SDK OAuth resource metadata fetch, GHSA-c9xm-49cp-xcr9](https://github.com/modelcontextprotocol/rust-sdk/security/advisories/GHSA-c9xm-49cp-xcr9) | The malicious metadata is served by the endpoint, but the vulnerable fetch occurs in a client. | No client-side test. `mcp-oauth-metadata-ssrf-001` probes a server's DCR handling, a different direction of trust. | Inspect the client SDK version or run a client-side test. |

`mcp-vulnerable-version-001` matches a closed set of self-reported component
names and versions documented in [the MCP rules](rules-mcp.md#mcp-vulnerable-version-001).
It covers recent filesystem and fetch server releases above when those reference
servers report their exact names and package versions. The git server reports
`mcp-git` with its package version from the 2026.10.10 release onward. It
cannot infer an installed SDK version from a generic server name. Every match
is an indicator, not exploit confirmation.

**Log-only evidence.** The current [MCP Python SDK logging guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/handlers/logging.md)
uses process logging on stderr; those records do not appear in an endpoint
response. Batesian cannot verify claims that depend on server audit logs or
long-term telemetry from HTTP alone. `mcp-log-optin-001` tests protocol log
notifications on the wire, not a server's log sink. The official
[A2A Python](https://github.com/a2aproject/a2a-python/security/advisories)
and [A2A JavaScript](https://github.com/a2aproject/a2a-js/security/advisories)
repositories listed no published advisories at the review date; their endpoint
misconfiguration checks remain in [the A2A rules](rules-a2a.md).
