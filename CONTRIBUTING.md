# Contributing to Batesian

Batesian is an adversarial red-team CLI for AI agent protocols. Contributions
are welcome, whether that is a new attack rule, a bug fix, or improved documentation.

## Before You Start

- Read the [project README](README.md) to understand what Batesian is and is not.
- Every rule must send crafted payloads to a live endpoint and evaluate real server
  responses (status, body, headers, timing, or out-of-band signals as defined in
  the rule). Rules should encode concrete protocol abuse checks, not static-page
  heuristics alone.
- By submitting a pull request, you agree your contributions are licensed under the
  same [Apache License 2.0](LICENSE) that covers this repository. No separate
  contributor agreement is required.

---

## Rule Authoring Guide

### Anatomy of a Rule

Every Batesian rule is composed of four parts that must all be present before
a rule is considered complete:

```
rules/<protocol>/<rule-id>.yaml            YAML descriptor
internal/attack/<protocol>/<name>.go       Go executor
internal/attack/<protocol>/<name>_test.go  Unit tests
testdata/...                               Vulnerable test server (Python)
```

Test servers in `testdata/` are typically **shared**: a single Python file may
host the routes for several related rules (for example,
`testdata/a2a_remaining_rules_server.py` covers three A2A rules). Add a new
server only when no existing one is a natural fit. See
[`testdata/README.md`](testdata/README.md) for the current registry, port
allocations, and dependencies.

### Naming Conventions

Rule IDs follow the pattern: `<protocol>-<attack-class>-<NNN>`

Examples: `a2a-push-ssrf-001`, `mcp-tool-poison-001`, `a2a-wellknown-hostinject-001`

Protocols: `a2a`, `mcp`

### YAML Rule File

Required fields:

```yaml
id: mcp-example-001
info:
  name: Short human-readable name
  author: your-github-handle
  severity: critical | high | medium | low | info
  description: |
    What vulnerability this tests, why it matters, and what an attacker
    can do if the assertion fires. Be specific about the protocol behavior.
  references:
    - https://relevant-spec-or-cve-url
  tags:
    - mcp
    - relevant-tag

attack:
  protocol: mcp | a2a
  type: attack-type-string   # must match a case in internal/engine/engine.go

assert:
  - condition: condition_name
    description: "What this assertion confirms"
    severity: high

remediation: |
  1. Concrete fix step.
  2. Another fix step.
```

### Go Executor

Executors live in `internal/attack/a2a/` or `internal/attack/mcp/` and implement
the `attack.Executor` interface:

```go
type Executor interface {
    Execute(ctx context.Context, target string, opts Options) ([]Finding, error)
}
```

Rules for executors:

1. Return `nil, nil` (not an error) if the target is not the right protocol or
   the precondition is not met. Errors are for unexpected failures, not clean skips.
2. Set `Confidence` explicitly on every `Finding`:
   - `attack.ConfirmedExploit`: the attack demonstrably succeeded.
   - `attack.RiskIndicator`: a suspicious pattern detected, but exploitability
     is not proven. Always include a note recommending manual verification.
3. Keep executors focused. One rule = one attack class. Shared helpers (session
   setup, SSE parsing) belong in package-level functions, not inlined.
4. Never use `time.Sleep` for more than 500ms. Use `context.WithTimeout`.
5. **YAML `probes` blocks are documentation-only for most rule types.** Some rules
   (e.g. `a2a-json-rpc-fuzz-001`) include a `probes:` list in YAML to document the
   payloads used, but the executor does not read these at runtime -- the payloads are
   hardcoded in Go so they can be dynamically generated (e.g. oversized strings) and
   guarantee correctness. If you add a `probes:` block to a new rule's YAML, include
   a comment explaining whether the executor reads it or not.

### Register the Executor

Add a `case` to the switch in `internal/engine/engine.go`:

```go
case "your-attack-type":
    return yourpkg.NewYourExecutor(rc), nil
```

---

## Validation Checklist

Every rule must pass all six steps before it can be merged. This is not optional.
A rule with only unit tests is not production-ready.

### Step 1: Unit Tests

Write tests in `internal/attack/<protocol>/<name>_test.go` using
`net/http/httptest` mock servers. Use the `package <proto>_test` convention
(external test package) to match the existing test style.

Required test cases for every rule:
- **Vulnerable server**: mock server that exhibits the vulnerability. Assert that
  the expected findings fire with the correct severity and `Confidence` value.
- **Secure server**: mock server where auth is enforced or the vulnerability is
  absent. Assert that zero findings (or zero `ConfirmedExploit` findings) are returned.
- **Precondition not met**: server that doesn't support the relevant capability.
  Assert clean skip (zero findings, no error).

Run tests: `go test ./internal/attack/...`

### Step 2: Testdata Server

Add the routes that exercise the vulnerability to a Python server in
`testdata/`. Prefer extending an existing server documented in
[`testdata/README.md`](testdata/README.md) when the protocol and theme match;
add a new file only if no existing server is a natural host. Either way:

- Bind to a documented port. New Starlette/uvicorn servers should pick the next
  free port in the `77xx` range, FastMCP servers in `87xx`, and "new style"
  servers in `31xx` (see `testdata/README.md`).
- Print startup confirmation lines so the caller can wait for readiness.
- Implement only the minimum routes needed to trigger the rule(s).
- Stay within the project test-server dependency set:
  `pip install starlette uvicorn httpx mcp`. Do not introduce new third-party
  packages without updating `testdata/README.md`.
- Include a module docstring listing every rule ID the server covers and how
  to run it.
- Update `testdata/README.md`'s registry table whenever you add a server,
  add a new rule to an existing server, or change a port.

### Step 3: Live Validation

Start the testdata server and run batesian against it:

```sh
# Start the server (in a separate terminal or background process)
python testdata/<name>_server.py

# Run the specific rule
./batesian scan --target http://127.0.0.1:<port> \
    --rule-ids <rule-id> --timeout 10 -v
```

Confirm:
- The expected finding(s) appear with the correct severity.
- The evidence field contains meaningful data (HTTP status, endpoint, snippet).
- The scan completes in a reasonable time (under 15s for a single rule).

### Step 4: Full Build and Test

```sh
go build ./...
go test ./...
```

Both must pass with zero failures before committing.

### Step 5: Linter

```sh
go vet ./...
golangci-lint run
```

Fix all reported issues. Both `go vet` and `golangci-lint` are enforced in CI
and must pass before a PR can be merged.

### Step 6: Production-Like Validation (Best Effort)

After the testdata server validation, attempt to run the rule against a real
deployed target that you have explicit permission to test. Suitable targets:

- Official reference implementations (e.g., `modelcontextprotocol/server-everything`
  in Docker, `a2aproject/a2a-samples` helloworld server)
- Your own deployed test instances
- Any public target with a documented security testing policy

Document the result (even "no findings on reference impl, as expected") in the
PR description.

---

## Commit Style

- Use conventional commit prefixes: `feat:`, `fix:`, `chore:`, `docs:`, `test:`
- One logical change per commit.
- Reference the rule ID in the commit message when adding or modifying a rule.

---

## Getting Help

For general questions, start a thread in the
[Discussions](https://github.com/calbebop/batesian/discussions) tab.
For bug reports or new rule requests, open an issue using one of the existing
templates. For security-sensitive matters, please follow the process in
[`SECURITY.md`](SECURITY.md) rather than opening a public issue.
