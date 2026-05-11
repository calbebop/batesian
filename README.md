# Batesian

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://golang.org)
[![Build](https://github.com/calbebop/batesian/actions/workflows/ci.yml/badge.svg)](https://github.com/calbebop/batesian/actions)

CLI for adversarial testing of [A2A](https://google.github.io/A2A/) and [MCP](https://modelcontextprotocol.io) stacks. It drives concrete protocol traffic (OAuth, callbacks, JWS, session boundaries, tool and metadata handling) and records outcomes as `confirmed` or `indicator`, with optional SARIF for CI.

![Batesian demo](docs/demo.gif)

> **Authorized use only.** Run Batesian only against systems you own or targets covered by explicit written permission. The CLI issues attack-shaped traffic. Use outside that scope is your responsibility.
>
> **Secrets and TLS.** Prefer `BATESIAN_TOKEN` or your secret manager over embedding long-lived bearer material in shared terminals, config repos, or CI logs. Use `--skip-tls` only when you must hit a host with intentionally broken TLS, such as a local lab on self-signed certificates.
>
> **Artifacts.** JSON and SARIF can contain URLs, snippets, and evidence. Treat exports the same way you treat other sensitive scanner output in shared pipelines.
>
> **Custom rules.** `--rules-dir` loads YAML from disk. Treat rule packs as untrusted input: they define what gets sent to the target.

## What ships

Bundled rules: 18 A2A, 17 MCP (35 total). Each maps to CWE-style references and remediation text in the catalogs:

- [A2A rules](docs/rules-a2a.md)
- [MCP rules](docs/rules-mcp.md)

## Quickstart

```bash
go install github.com/calbebop/batesian/cmd/batesian@latest

batesian probe --target https://agent.example.com --protocol a2a

batesian scan --target https://agent.example.com --output sarif > results.sarif

batesian scan --target https://agent.example.com --rule-ids a2a-push-ssrf-001,mcp-tool-poison-001

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

batesian init
```

`probe` is reconnaissance (table or JSON). It does not emit SARIF. For flags, filters, config files, OAuth, and extra rule paths: `batesian scan --help`.

## Rule packs

Rules are YAML. New checks can ship without recompiling the binary. Authoring, schema, and review expectations are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Python SDK

Version **0.3.0** (see `sdk/python/pyproject.toml`). The SDK shells out to the same `batesian` binary (`BATESIAN_BIN` or PATH).

```python
from batesian import Scanner

scanner = Scanner(target="https://agent.example.com")
results = scanner.run(rules=["a2a-push-ssrf-001", "mcp-tool-poison-001"])

for finding in results.findings:
    print(f"[{finding.severity}] {finding.rule_id}: {finding.title}")

assert results.critical_count == 0
```

Install and CI patterns: [`sdk/python/`](sdk/python/).

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
