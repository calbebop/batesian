# Batesian

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://golang.org)
[![Build](https://github.com/calbebop/batesian/actions/workflows/ci.yml/badge.svg)](https://github.com/calbebop/batesian/actions)

CLI for adversarial testing of [A2A](https://google.github.io/A2A/) and [MCP](https://modelcontextprotocol.io) stacks. It drives concrete protocol traffic (OAuth audience/scope/DCR, push-notification callbacks, JWS card signatures, session and task boundaries, agent-card handling) and records outcomes as `confirmed` or `indicator`, with optional SARIF for CI.

![Batesian demo](docs/demo.gif)

> **Authorized use only.** Run Batesian only against systems you own or targets covered by explicit written permission. The CLI issues attack-shaped traffic. Use outside that scope is your responsibility.
>
> **Secrets and TLS.** Prefer `BATESIAN_TOKEN` or your secret manager over embedding long-lived bearer material in shared terminals, config repos, or CI logs. Use `--skip-tls` only when you must hit a host with intentionally broken TLS, such as a local lab on self-signed certificates.
>
> **Artifacts.** JSON and SARIF can contain URLs, snippets, and evidence. Treat exports the same way you treat other sensitive scanner output in shared pipelines.
>
> **Custom rules.** `--rules-dir` loads YAML from disk. Treat rule packs as untrusted input: they define what gets sent to the target.

## What ships

Bundled rules: **14 A2A, 12 MCP (26 total)**. The set is deliberately narrow - every rule targets MCP/A2A-specific semantics, not generic web hygiene that `nuclei`/ZAP already cover. Each rule maps to CWE references and remediation text in the catalogs:

- [A2A rules](docs/rules-a2a.md) (14)
- [MCP rules](docs/rules-mcp.md) (12)

Coverage spans:

- **OAuth & token validation** - OAuth 2.1 / DCR scope escalation, audience binding, token replay, version-downgrade bypass, forged-token acceptance
- **Agent-card trust (A2A)** - JWS signatures, canonicalization, cache/freshness, required-extension downgrade, host-header injection, unauthenticated extended card
- **Request & task integrity** - task IDOR, agent-role injection, artifact tampering, SEP-2243 header/body routing, SSE resumption replay
- **Multi-party isolation** - cross-tenant isolation, session/context fixation, delegation chain-of-custody
- **SSRF & secret leakage** - push-notification SSRF, push control-plane binding, OAuth discovery/metadata SSRF, credential leakage into responses
- **Unauthenticated access** - exposed MCP resources and prompt templates

### How findings are reported

- **Confidence** - `confirmed` (the attack demonstrably succeeded) or `indicator` (a suspicious posture that needs manual verification).
- **Coalescing** - overlapping findings from rules in the same vulnerability class are merged by default; disable with `--no-coalesce`.
- **JSON output** - `scan --output json` writes JSON to stdout (status goes to stderr), so `batesian scan --output json | jq` works.

## Quickstart

```bash
go install github.com/calbebop/batesian/cmd/batesian@latest

batesian probe --target https://agent.example.com --protocol a2a

batesian scan --target https://agent.example.com --output sarif > results.sarif

batesian scan --target https://agent.example.com --rule-ids a2a-push-ssrf-001,mcp-resources-unauth-001

batesian scan --target https://mcp.example.com --token "$TOKEN"

batesian scan --target https://mcp.example.com \
  --token-url https://auth.example.com/oauth/token \
  --client-id my-client \
  --client-secret "$CLIENT_SECRET" \
  --oauth-scopes mcp:read,mcp:write

batesian scan --target https://mcp.example.com \
  --auth-url https://auth.example.com/authorize \
  --token-url https://auth.example.com/oauth/token \
  --client-id my-client \
  --oauth-scopes mcp:read

batesian scan --target https://agent.example.com \
  --principal name=tenant-a,token="$TOKEN_A",tenant=A \
  --principal name=tenant-b,token="$TOKEN_B",tenant=B

batesian init
```

`probe` is reconnaissance (table or JSON). It does not emit SARIF. For flags, filters, config files, OAuth, and extra rule paths: `batesian scan --help`.

## Rule packs

Rules are YAML. New checks can ship without recompiling the binary. Authoring, schema, and review expectations are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Build and test

```bash
make build
make test
```

Or: `go build -o bin/batesian ./cmd/batesian` and `go test -race ./...`.

## Contributing

Rules and code are welcome under [Apache 2.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerable fixtures and port layout for tests: [`testdata/README.md`](testdata/README.md).

## References

- [A2A Protocol Specification](https://google.github.io/A2A/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
- [Unit 42: Agent Session Smuggling in A2A Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)
- [OWASP GenAI Security Project](https://genai.owasp.org)

## License

Apache 2.0. See [LICENSE](LICENSE).
