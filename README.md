# Batesian

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://golang.org)
[![Build](https://github.com/calbebop/batesian/actions/workflows/ci.yml/badge.svg)](https://github.com/calbebop/batesian/actions)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/calbebop/batesian/badge)](https://scorecard.dev/viewer/?uri=github.com/calbebop/batesian)

CLI for adversarial testing of [A2A](https://a2a-protocol.org) and [MCP](https://modelcontextprotocol.io) stacks. It drives concrete protocol traffic (OAuth audience/scope/DCR, push-notification callbacks, JWS card signatures, session and task boundaries, agent-card handling) and records outcomes as `confirmed` or `indicator`, with optional SARIF for CI.

![Batesian demo](docs/demo.gif)

> **Authorized use only.** Run Batesian only against systems you own or targets covered by explicit written permission. The CLI issues attack-shaped traffic. Use outside that scope is your responsibility. To review the traffic a scan would generate before authorizing it, run `scan --dry-run`: it records and prints every request and sends nothing.
>
> **Secrets and TLS.** Prefer `BATESIAN_TOKEN` or your secret manager over embedding long-lived bearer material in shared terminals, config repos, or CI logs. Use `--skip-tls` only when you must hit a host with intentionally broken TLS, such as a local lab on self-signed certificates.
>
> **Artifacts.** JSON and SARIF can contain URLs, snippets, and evidence. Treat exports the same way you treat other sensitive scanner output in shared pipelines.
>
> **Custom rules.** `--rules-dir` loads YAML from disk. Treat rule packs as untrusted input: they define what gets sent to the target.

## What ships

Bundled rules: **17 A2A, 19 MCP (36 total)**. The set is deliberately narrow - every rule targets MCP/A2A-specific semantics, not generic web hygiene that `nuclei`/ZAP already cover. Each rule maps to CWE references and remediation text in the catalogs:

- [A2A rules](docs/rules-a2a.md) (17)
- [MCP rules](docs/rules-mcp.md) (18)

Rules are validated against third-party reference implementations, not only against the bundled fixtures. [Validation results](docs/validation-results.md) records what fires, what correctly stays silent on a server with no authentication at all, and the scanner defects that exercise has found.

Coverage spans:

- **OAuth & token validation** - OAuth 2.1 / DCR scope escalation, audience binding, token replay, version-downgrade bypass, forged-token acceptance, redirect_uri confused deputy
- **Agent-card trust (A2A)** - JWS signatures, canonicalization, cache/freshness, required-extension downgrade, host-header injection, unauthenticated extended card, declared-but-unenforced auth
- **Request & task integrity** - task IDOR, agent-role injection, artifact tampering, SEP-2243 header/body routing, SSE resumption replay
- **Multi-party isolation** - cross-tenant isolation, session/context fixation, delegation chain-of-custody, cross-principal task cancellation, cross-context MCP task and result access
- **SSRF & secret leakage** - push-notification SSRF, push control-plane binding, OAuth discovery/metadata SSRF, credential leakage into responses
- **Unauthenticated & cross-origin access** - exposed MCP tools, resources, prompt templates, completion suggestions, and log-level control, Streamable HTTP Origin validation (DNS rebinding)

## Install

Pre-built, signed binaries for Linux, macOS, and Windows (amd64/arm64) are attached to every [release](https://github.com/calbebop/batesian/releases):

```bash
# Download the archive for your platform from the Releases page, then:
tar xzf batesian_<version>_linux_x86_64.tar.gz
./batesian --help
```

Or build from source with Go 1.25+:

```bash
go install github.com/calbebop/batesian/cmd/batesian@latest
```

## Quickstart

```bash
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

# When the target resolves the tenant from a routing header rather than the token,
# give each identity its header, or the multi-tenant rules compare two identities
# the server cannot tell apart. header= repeats per principal.
batesian scan --target https://agent.example.com \
  --principal name=tenant-a,token="$TOKEN_A",tenant=A,header=X-Tenant-Id:A \
  --principal name=tenant-b,token="$TOKEN_B",tenant=B,header=X-Tenant-Id:B

batesian scan --target https://agent.example.com --dry-run

batesian scan --target https://mcp.example.com --proxy 127.0.0.1:8080 --skip-tls

batesian init
```

`--proxy` routes every request through an intercepting proxy so a whole scan can be
reviewed in Burp or ZAP, and pairs with `--skip-tls` because such proxies present
their own CA. With no flag, `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` are honoured;
note that Go does not send loopback targets through an environment proxy, so a scan
against `127.0.0.1` needs the explicit flag.

`probe` is reconnaissance (table or JSON). It does not emit SARIF. `batesian init` writes an annotated `batesian.yaml` to the current directory (it will not overwrite an existing one) so targets, tokens, and rule selections can live in version-controlled config. For flags, filters, config files, OAuth, and extra rule paths: `batesian scan --help`.

## CI integration

`scan --output sarif` writes SARIF 2.1.0 to stdout. Upload it to the GitHub Security tab with the standard action:

```yaml
name: batesian
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # upload SARIF to the Security tab
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: go install github.com/calbebop/batesian/cmd/batesian@latest
      - run: batesian scan --target https://agent.example.com --output sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Findings surface as code-scanning alerts. `scan` exits non-zero only on an operational error, not on findings, so gating is handled by the Security tab (or by parsing `--output json`).

## Rule packs

Rules are YAML. New checks can ship without recompiling the binary. Authoring, schema, and review expectations are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

Rules and code are welcome under [Apache 2.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerable fixtures and port layout for tests: [`testdata/README.md`](testdata/README.md).

## References

- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
- [Unit 42: Agent Session Smuggling in A2A Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)
- [OWASP GenAI Security Project](https://genai.owasp.org)

## License

Apache 2.0. See [LICENSE](LICENSE).
