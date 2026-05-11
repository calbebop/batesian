# batesian Python SDK

Python wrapper around the [Batesian](https://github.com/calbebop/batesian) red-team CLI for AI agent protocols.

## Requirements

- Python 3.9+
- The `batesian` CLI binary installed and on `PATH`

```bash
go install github.com/calbebop/batesian/cmd/batesian@latest
```

## Install

> **PyPI release pending.** A `pip install batesian` package will be published shortly.
> Until then, install directly from the repository.

From Git:

```bash
pip install "batesian @ git+https://github.com/calbebop/batesian.git@main#subdirectory=sdk/python"
```

Or from source (within this directory):

```bash
pip install -e .
```

## Usage

```python
from batesian import Scanner

scanner = Scanner(target="https://agent.example.com")
results = scanner.run(rules=["a2a-push-ssrf-001", "mcp-tool-poison-001"])

for finding in results.findings:
    print(f"[{finding.severity}] {finding.rule_id}: {finding.title}")

assert results.critical_count == 0
```

### Scan all rules for a protocol

```python
results = scanner.run(protocol="mcp")
print(f"Found {results.high_count} high-severity issues")
```

### Filter by severity

```python
results = scanner.run(severities=["critical", "high"])
```

### Authenticated scan (static token)

```python
scanner = Scanner(target="https://mcp.example.com", token="my-bearer-token")
results = scanner.run()
```

### Authenticated scan (OAuth 2.0 client credentials)

```python
scanner = Scanner(
    target="https://mcp.example.com",
    token_url="https://auth.example.com/oauth/token",
    client_id="my-client-id",
    client_secret="my-client-secret",
    oauth_scopes=["mcp:read", "mcp:write"],
)
results = scanner.run()
```

### Authenticated scan (OAuth 2.0 authorization code + PKCE)

PKCE is interactive: the underlying `batesian` CLI opens a browser, the user
consents, and the CLI captures the redirect on a localhost listener. The SDK
forwards the flags; the browser flow and token exchange happen inside the Go
binary. Use this when your IdP requires user consent (rather than client
credentials).

```python
scanner = Scanner(
    target="https://mcp.example.com",
    auth_url="https://auth.example.com/authorize",
    token_url="https://auth.example.com/oauth/token",
    client_id="my-client-id",
    oauth_scopes=["mcp:read"],
)
results = scanner.run()
```

For headless or CI environments, set `no_browser=True` and copy the printed
authorization URL manually. Use `redirect_port=...` if your IdP has a fixed
redirect URI registered or the default port is taken:

```python
scanner = Scanner(
    target="https://mcp.example.com",
    auth_url="https://auth.example.com/authorize",
    token_url="https://auth.example.com/oauth/token",
    client_id="my-client-id",
    oauth_scopes=["mcp:read"],
    redirect_port=8765,
    no_browser=True,
)
results = scanner.run()
```

### Use in CI (fail on critical findings)

```python
import sys
from batesian import Scanner

scanner = Scanner(target="https://agent.example.com")
results = scanner.run()

if results.critical_count > 0:
    for f in results.findings_by_severity("critical"):
        print(f"CRITICAL: {f.title}")
    sys.exit(1)
```

### Probe a target for attack surface

The `probe` command discovers the agent or MCP server's capabilities and flags
potential attack surface without running full exploit checks.

```python
scanner = Scanner(target="https://agent.example.com")

# Probe A2A (default)
info = scanner.probe()
print(info)

# Probe MCP
info = scanner.probe(protocol="mcp")
print(info)
```

`probe()` returns the raw JSON dict from the CLI. Use it to understand the
target before running a full scan. It defaults to the `"a2a"` protocol when
`protocol` is omitted (matching the CLI default).

## API Reference

### `Scanner`

| Parameter | Type | Description |
|---|---|---|
| `target` | `str` | Base URL of the agent or MCP server |
| `binary_path` | `str` | Explicit path to batesian binary (optional) |
| `token` | `str` | Bearer token for authenticated requests |
| `token_url` | `str` | OAuth 2.0 token endpoint |
| `client_id` | `str` | OAuth 2.0 client ID |
| `client_secret` | `str` | OAuth 2.0 client secret |
| `oauth_scopes` | `list[str]` | OAuth 2.0 scopes |
| `oauth_audience` | `str` | OAuth 2.0 audience (Auth0/Okta-style) |
| `auth_url` | `str` | OAuth 2.0 authorization endpoint URL (enables PKCE flow) |
| `redirect_port` | `int` | Local port for the PKCE callback (default in CLI: 9876) |
| `no_browser` | `bool` | Print the authorization URL instead of auto-opening a browser |
| `timeout` | `int` | Per-request HTTP timeout in seconds (default: 10) |
| `skip_tls` | `bool` | Skip TLS verification (default: False) |
| `config` | `str` | Path to `batesian.yaml` config file |
| `verbose` | `bool` | Forward `-v` to the CLI (verbose output to stderr; default: False) |

### `Results`

| Property | Type | Description |
|---|---|---|
| `findings` | `list[Finding]` | All findings from the scan |
| `critical_count` | `int` | Number of critical-severity findings |
| `high_count` | `int` | Number of high-severity findings |
| `medium_count` | `int` | Number of medium-severity findings |
| `confirmed_count` | `int` | Findings with confirmed exploit confidence |
| `findings_by_severity(s)` | `list[Finding]` | Filter findings by severity string |
| `findings_for_rule(id)` | `list[Finding]` | Filter findings by rule ID |

### `Finding`

| Property | Type | Description |
|---|---|---|
| `rule_id` | `str` | Rule identifier (e.g. `a2a-push-ssrf-001`) |
| `severity` | `str` | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | `str` | `confirmed` or `indicator` |
| `title` | `str` | Short finding description |
| `description` | `str` | Detailed explanation |
| `evidence` | `str` | Raw evidence from the probe |
| `remediation` | `str` | Fix guidance |
| `is_confirmed` | `bool` | True when confidence is `confirmed` |

### `Scanner` methods

| Method | Returns | Description |
|---|---|---|
| `run(**kwargs)` | `Results` | Execute a full scan; raises `ScanError` on failure |
| `probe(*, protocol)` | `dict` | Run the probe command; returns raw JSON; raises `ScanError` on failure |

## Binary discovery

The SDK searches for the `batesian` binary in this order:

1. `binary_path` constructor argument
2. `BATESIAN_BIN` environment variable
3. `batesian` / `batesian.exe` on `PATH`
4. `~/go/bin/batesian`, `/usr/local/bin/batesian`

## License

Apache 2.0
