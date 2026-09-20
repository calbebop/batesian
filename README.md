# Batesian

[![Build](https://github.com/calbebop/batesian/actions/workflows/ci.yml/badge.svg)](https://github.com/calbebop/batesian/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/calbebop/batesian)](https://github.com/calbebop/batesian/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/calbebop/batesian/badge)](https://scorecard.dev/viewer/?uri=github.com/calbebop/batesian)

**Protocol-aware adversarial testing for A2A and MCP.**

Batesian is a single-binary CLI that tests deployed AI agent infrastructure with real protocol traffic. It exercises authorization, identity, discovery, task isolation, callbacks, sessions, and tool boundaries, then reports evidence as a confirmed exploit or a risk indicator. Table, JSON, and SARIF output support local testing and CI.

![Batesian demo](docs/demo.gif)

> [!CAUTION]
> Run Batesian only against systems you own or have explicit written permission to test. Scans send attack-shaped traffic and some rules can change server-side state. Use `scan --dry-run` to inspect the request plan without sending traffic.

## Highlights

- **47 bundled rules:** 19 A2A and 28 MCP checks focused on protocol-specific weaknesses.
- **Active verification:** rules evaluate live responses, state transitions, and out-of-band callbacks instead of relying on banners or static heuristics.
- **Evidence-aware results:** confirmed exploits are separated from indicators that require manual validation.
- **Honest coverage:** skipped, unsupported, and errored rules remain visible instead of being reported as clean.
- **CI-ready output:** SARIF 2.1.0 integrates with GitHub code scanning; JSON supports custom pipelines.
- **Controlled execution:** dry runs, exact rule filters, proxy support, strict configuration, and explicit approval for mutating MCP tools.

## Install

### Release artifacts

Download the latest archive from [GitHub Releases](https://github.com/calbebop/batesian/releases/latest).

| Platform | Architectures | Archive |
| --- | --- | --- |
| Linux | x86_64, arm64 | `.tar.gz` |
| macOS | x86_64, arm64 | `.tar.gz` |
| Windows | x86_64 | `.zip` |

```bash
# Example: Linux x86_64
tar -xzf batesian_<version>_linux_x86_64.tar.gz
sudo install -m 0755 batesian /usr/local/bin/batesian
batesian --version
```

Current releases include SHA-256 checksums, a Sigstore bundle for the checksum file, a CycloneDX SBOM for every archive, and SLSA build provenance.

### Go toolchain

Go 1.25 or newer is required when installing from source:

```bash
go install github.com/calbebop/batesian/cmd/batesian@latest
```

## Quick start

List the available checks, probe the target, review the attack plan, and then run a scan:

```bash
batesian rules --protocol mcp --severity critical,high

batesian probe --target https://agent.example.com --protocol a2a

batesian scan --target https://agent.example.com --dry-run

batesian scan --target https://agent.example.com
```

`probe` performs lightweight reconnaissance and produces table or JSON output. `scan` executes the applicable attack rules and supports table, JSON, or SARIF output.

Run a smaller rule set with protocol, severity, tag, or rule-ID filters:

```bash
batesian scan --target https://mcp.example.com \
  --protocol mcp \
  --severity critical,high

batesian scan --target https://agent.example.com \
  --rule-ids a2a-push-ssrf-001,a2a-task-idor-001
```

## Coverage

The bundled catalogs contain [19 A2A rules](docs/rules-a2a.md) and [28 MCP rules](docs/rules-mcp.md). Every descriptor maps to compiled attack logic, CWE references, and remediation guidance.

| Area | Examples |
| --- | --- |
| OAuth and token handling | Audience and scope validation, DCR, token replay, metadata SSRF, redirect confusion |
| Agent identity and discovery | Agent Card trust, JWS validation, host injection, extension downgrade, extended-card access |
| Task and tenant isolation | Task IDOR, cross-principal cancellation and enumeration, context fixation, delegation integrity |
| Push notifications | Callback SSRF, control-plane binding, missing callback authentication |
| MCP authorization surfaces | Unauthenticated tools, resources, prompts, completions, and logging controls |
| Transport boundaries | Origin validation, header/body routing, protocol downgrade, SSE replay, session misuse |
| Tool and manifest integrity | Argument traversal, hidden payloads, description injection, duplicate-name shadowing, manifest drift |
| Deployment exposure | Shadow listeners, secret leakage, and known vulnerable component versions |

The suite is validated against vulnerable fixtures and third-party reference implementations. See [validation results](docs/validation-results.md) for expected findings, secure controls, and known applicability limits.

## Authentication and identity

### Bearer token

Prefer the environment variable so credentials stay out of process arguments. Read it without echoing or recording the value in shell history:

```bash
read -rsp "Batesian token: " BATESIAN_TOKEN && echo
export BATESIAN_TOKEN
batesian scan --target https://mcp.example.com
```

`--token` is also available for short-lived credentials.

### OAuth client credentials

```bash
batesian scan --target https://mcp.example.com \
  --token-url https://auth.example.com/oauth/token \
  --client-id my-client \
  --client-secret "$CLIENT_SECRET" \
  --oauth-scopes mcp:read,mcp:write
```

### Authorization code with PKCE

```bash
batesian scan --target https://mcp.example.com \
  --auth-url https://auth.example.com/authorize \
  --token-url https://auth.example.com/oauth/token \
  --client-id my-client \
  --oauth-scopes mcp:read
```

### Multiple principals

Cross-tenant and cross-principal checks require distinct identities. Add routing headers when the target derives tenant identity from a header rather than the token:

```bash
batesian scan --target https://agent.example.com \
  --principal name=tenant-a,token="$TOKEN_A",tenant=A,header=X-Tenant-Id:A \
  --principal name=tenant-b,token="$TOKEN_B",tenant=B,header=X-Tenant-Id:B
```

## Safe operation

- `--dry-run` records the planned requests and sends no network traffic. Requests that depend on live responses, acquired tokens, or callbacks cannot be expanded fully until a real scan.
- `--proxy 127.0.0.1:8080` routes scan and OAuth traffic through an intercepting proxy. Environment proxy variables are honored when the flag is absent; Go excludes loopback targets from environment proxies.
- `--skip-tls` disables certificate validation and should be limited to controlled labs or intercepting proxies.
- Target-advertised OAuth endpoints are restricted to the target origin. Use `--oauth-origin https://login.example.com` to approve an additional exact origin.
- Some OAuth rules temporarily register clients and remove them when RFC 7592 management is available.
- The scope-confusion rule invokes a mutating tool only when its exact name is approved with `--mcp-scope-tool`.
- JSON and SARIF may contain URLs, response snippets, and evidence. Treat them as sensitive security artifacts.

## Results and exit behavior

| Output | Intended use |
| --- | --- |
| `table` | Interactive review in a terminal |
| `json` | Automation and custom policy gates |
| `sarif` | GitHub code scanning and SARIF-compatible platforms |

A finding is marked `confirmed` only when the rule observes exploit evidence. An `indicator` identifies a risky condition without claiming successful exploitation.

`scan` exits non-zero for command-level failures, including invalid configuration or filters that select no rules. Findings and individual rule skips do not change the process exit code. SARIF invocation metadata records completed, skipped, and errored rules and sets `executionSuccessful` to `false` when coverage is incomplete.

## CI integration

The following workflow uploads A2A findings to GitHub code scanning:

```yaml
name: Batesian

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/setup-go@v7
        with:
          go-version: '1.25'
      - run: go install github.com/calbebop/batesian/cmd/batesian@v1.7.0
      - name: Scan
        env:
          BATESIAN_TOKEN: ${{ secrets.BATESIAN_TOKEN }}
        run: batesian scan --target https://agent.example.com --protocol a2a --output sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

Pin the Batesian version used in CI and update it deliberately. Select only protocols and rules whose authentication, identity, and callback prerequisites the job can provide; skipped or errored rules are not evidence of a clean target. More deployment patterns are documented in [CI/CD integration](docs/ci-cd.md).

## Configuration and rule packs

Generate an annotated configuration file with:

```bash
batesian init
```

This writes `batesian.yaml` in the current directory and will not overwrite an existing file. Explicit or discovered configuration must be readable, contain one YAML document, and use known keys.

`--rules-dir` supplements the built-in catalog with strict YAML descriptors. Descriptors select compiled executors and provide report metadata; they cannot define arbitrary network behavior. A rule pack loads atomically, so one unreadable, invalid, or oversized descriptor stops the command instead of producing a partial scan.

## Contributing and security

Rules, fixes, and documentation are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the rule architecture, test requirements, and local workflow. Vulnerable fixtures and their port assignments are documented in [testdata/README.md](testdata/README.md).

Report vulnerabilities in Batesian privately according to [SECURITY.md](SECURITY.md).

## References

- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Unit 42: Agent Session Smuggling in A2A Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)
- [OWASP GenAI Security Project](https://genai.owasp.org)

## License

Apache 2.0. See [LICENSE](LICENSE).
