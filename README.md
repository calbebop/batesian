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
> **State on the target.** Three OAuth rules temporarily register clients and remove them when RFC 7592 management is available. The scope-confusion rule can invoke mutating tools only when their exact names are approved with `--mcp-scope-tool`; those calls may have side effects.
>
> **Artifacts.** JSON and SARIF can contain URLs, snippets, and evidence. Treat exports the same way you treat other sensitive scanner output in shared pipelines.
>
> **Custom rules.** `--rules-dir` loads strict YAML descriptors from disk. Review rule packs before use: they select compiled executors and supply report metadata, but cannot define arbitrary traffic.

## What ships

Bundled rules: **19 A2A, 28 MCP (47 total)**. The set is deliberately narrow - every rule targets MCP/A2A-specific semantics, not generic web hygiene that `nuclei`/ZAP already cover. Each rule maps to CWE references and remediation text in the catalogs:

- [A2A rules](docs/rules-a2a.md) (18)
- [MCP rules](docs/rules-mcp.md) (21)

Rules are validated against third-party reference implementations, not only against the bundled fixtures. [Validation results](docs/validation-results.md) records what fires, what correctly stays silent on a server with no authentication at all, and the scanner defects that exercise has found.

Coverage spans:

- **OAuth & token validation** - OAuth 2.1 / DCR scope escalation, audience binding, token replay, version-downgrade bypass, forged-token acceptance, redirect_uri confused deputy, tool-level scope enforcement
- **Agent-card trust (A2A)** - JWS signatures, canonicalization, cache/freshness, required-extension downgrade, host-header injection, unauthenticated extended card, declared-but-unenforced auth
- **Push notification authenticity** - callbacks that drop the configured integrity token, so receivers cannot distinguish genuine events from forgeries
- **Request & task integrity** - task IDOR, agent-role injection, artifact tampering, SEP-2243 header/body routing, SSE resumption replay
- **Multi-party isolation** - cross-tenant isolation, cross-principal task enumeration, session/context fixation, session id accepted as a credential, delegation chain-of-custody, cross-principal task cancellation, cross-context MCP task and result access
- **SSRF & secret leakage** - push-notification SSRF, push control-plane binding, OAuth discovery/metadata SSRF, credential leakage into responses
- **Shadow surfaces** - unauthenticated inspector/dashboard listeners on adjacent ports, graded by whether a foreign origin can reach them
- **Origin validation quality** - prefix-forged origins that slip past startswith()-style validators while unrelated origins are correctly refused
- **Tool manifest integrity** - hidden-character payloads, description injection patterns, duplicate-name shadowing, and manifest drift between consecutive reads (OWASP MCP03)
- **Component exposure** - self-reported server identity matched against a closed table of published MCP advisories
- **Unauthenticated & cross-origin access** - exposed MCP tools, resources, prompt templates, completion suggestions, and log-level control, Streamable HTTP Origin validation (DNS rebinding)
- **Tool argument integrity** - path traversal in read-only MCP tool arguments (sandbox escape via resolution evidence, zero content read)

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

Target-advertised OAuth URLs are confined to the target's exact origin. When a
deployment uses a separate authorization server, add its origin to the scan scope
with `--oauth-origin https://login.example.com` (or `oauth_origins` in config).

The scope-confusion rule discovers mutating tools but does not invoke them unless
each exact name is approved with `--mcp-scope-tool` or `mcp_scope_tools`.

`probe` is reconnaissance (table or JSON). It does not emit SARIF. `batesian init` writes an annotated `batesian.yaml` to the current directory (it will not overwrite an existing one) so targets, tokens, and rule selections can live in version-controlled config. Missing auto-discovered configuration is optional; an explicit or discovered file that cannot be read or validated stops the scan. Config keys are strict and each file must contain at most one YAML document. For flags, filters, config files, OAuth, and extra rule paths: `batesian scan --help`.

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

Findings surface as code-scanning alerts. SARIF invocation metadata records
completed, skipped, and errored rules; `executionSuccessful` is false when
coverage is incomplete. GitHub accepts but does not display these fields, so CI
can enforce coverage with:

```sh
jq -e 'all(.runs[].invocations[]; .executionSuccessful)' results.sarif
```

`scan` exits non-zero only on a command-level error, not findings or per-rule
skips. Gate findings through the Security tab or `--output json`.

## Rule packs

Rules pair YAML metadata with compiled Go executors. New descriptors for existing executors can load at runtime; new attack logic requires recompilation. Authoring, schema, and review expectations are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

Rules and code are welcome under [Apache 2.0](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerable fixtures and port layout for tests: [`testdata/README.md`](testdata/README.md).

## References

- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Unit 42: Agent Session Smuggling in A2A Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)
- [OWASP GenAI Security Project](https://genai.owasp.org)

## License

Apache 2.0. See [LICENSE](LICENSE).
