# CI/CD Integration

Batesian outputs SARIF, consumed by SARIF tooling (DAST viewers, dashboards) and
uploadable to GitHub Code Scanning. Note that Batesian findings are network
targets, not files in the repository, so GitHub surfaces them as alerts without
source-line annotations (it resolves SARIF locations as repository paths).
The examples below use the current `main` branch because their coverage gates
depend on JSON rule outcomes and SARIF invocation metadata. Older releases may
not include these fields. Pin a reviewed commit or release tag in real CI.

SARIF alert messages include a short evidence excerpt. Full evidence and attack
chain steps are in result properties. When a finding differs from its rule's
default severity, its SARIF rule ID gains a severity suffix, such as
`mcp-example-001/medium`. The original ID remains in `sourceRuleId`. This keeps
GitHub's rule-level security score aligned with each result. Fingerprints use
the rule, finding text, and target path; query strings do not affect identity.
The revised fingerprints may cause existing alerts to appear new once.

## GitHub Actions

### Basic scan (upload SARIF to Code Scanning)

```yaml
# .github/workflows/agent-security.yml
name: Agent Security Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    # Run daily at midnight UTC
    - cron: '0 0 * * *'

jobs:
  batesian:
    name: Batesian adversarial scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # Required to upload SARIF to Code Scanning

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v7
        with:
          go-version: '1.26.9'

      - name: Install Batesian
        run: go install github.com/calbebop/batesian/cmd/batesian@main

      - name: Run scan (SARIF output)
        run: |
          batesian scan \
            --target "$AGENT_TARGET_URL" \
            --protocol a2a \
            --output sarif \
            --timeout 30 \
            > results.sarif
        env:
          AGENT_TARGET_URL: ${{ vars.AGENT_TARGET_URL }}
          # Optional: bearer token for authenticated targets
          BATESIAN_TOKEN: ${{ secrets.AGENT_TOKEN }}

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: batesian
        # Always upload, even if the scan found vulnerabilities, so results
        # appear in the Security tab regardless of exit code.
        if: always()

      - name: Require complete rule coverage
        run: |
          jq -e '
            (.runs | length) == 1 and
            (.runs[0].invocations | length) == 1 and
            (.runs[0].invocations[0] |
              .executionSuccessful == true and
              .properties.rulesSelected > 0 and
              .properties.rulesCompleted == .properties.rulesSelected and
              .properties.rulesSkipped == 0 and
              .properties.rulesErrored == 0)
          ' results.sarif
```

Skipped and errored rules are stored as SARIF invocation notifications, not
alerts. GitHub accepts these fields but does not display them, so the explicit
coverage check prevents a partial scan from passing unnoticed. Select only rules
whose identity, authentication, and callback prerequisites the job can meet.
The gate checks selected rules, not every rule in the catalog.

### Fail the build on findings above a severity threshold

Batesian exits `0` whether or not findings are present (SARIF output is the
primary mechanism). To fail the build, combine JSON output with `jq`:

```yaml
      - name: Run scan (fail on critical/high)
        run: |
          batesian scan \
            --target ${{ vars.AGENT_TARGET_URL }} \
            --output json \
            --timeout 30 \
          | jq -e '
              (.findings // [])
              | map(select(.severity == "critical" or .severity == "high"))
              | length == 0
            '
```

This exits non-zero if any critical or high findings are present.

### Check JSON report coverage

Scan JSON has `schema_version: 1`; incompatible schema changes increment it.
The `scanner` object records the build version,
commit, and date. The `ruleset` object records the loaded and selected rule counts,
whether a supplemental rule directory was configured, and a SHA-256 hash of the
loaded rule descriptors. The hash ignores rule-file ordering and YAML comments.

`rule_outcomes` has one entry per selected rule, in execution order. Status is
`findings`, `no_findings`, `skipped`, or `error`; each entry includes its finding
count and any skip reason or error. Outcomes are captured before coalescing, so
the finding count can exceed the coalesced `summary.total`. The existing
`findings`, `skipped`, `errors`, and `summary` fields remain available.

To require complete coverage in a JSON pipeline:

```sh
jq -e '
  .schema_version == 1 and
  .ruleset.selected > 0 and
  (.rule_outcomes | length) == .ruleset.selected and
  all(.rule_outcomes[]; .status == "findings" or .status == "no_findings")
' results.json
```

Pin the expected rule IDs or count in your pipeline if a catalog change must not
silently reduce the selected set.

### Scan specific protocols only

```yaml
      # A2A only
      - run: batesian scan --target ${{ vars.AGENT_TARGET_URL }} --protocol a2a --output sarif > results.sarif

      # MCP only
      - run: batesian scan --target ${{ vars.AGENT_TARGET_URL }} --protocol mcp --output sarif > results.sarif
```

### Scan specific rule IDs

```yaml
      # Run the SSRF and IDOR rules only
      - run: |
          batesian scan \
            --target ${{ vars.AGENT_TARGET_URL }} \
            --rule-ids a2a-push-ssrf-001,a2a-task-idor-001 \
            --output sarif > results.sarif
```

## Repository Variables and Secrets

| Name | Type | Description |
|---|---|---|
| `AGENT_TARGET_URL` | Variable (not secret) | The full URL of the agent endpoint to test. Example: `https://agent.example.com` |
| `AGENT_TOKEN` | Secret | Bearer token for authenticated A2A/MCP endpoints. Leave unset for unauthenticated targets. |

Set these in **Settings > Secrets and variables > Actions**.

## OOB / SSRF detection in CI

The push-notification SSRF rule (`a2a-push-ssrf-001`) and the OAuth metadata
SSRF rule (`mcp-oauth-metadata-ssrf-001`) confirm findings via an out-of-band
callback. Each rule starts a local HTTP listener automatically for the run, so
no extra flag is needed:

```yaml
      - name: Run scan (OOB SSRF detection is automatic)
        run: |
          batesian scan \
            --target ${{ vars.AGENT_TARGET_URL }} \
            --output sarif \
            > results.sarif
```

The local listener binds a random port and derives the callback URL from the
host's detected outbound interface IP (typically a private or RFC 1918 address).
On GitHub Actions runners this IP is not publicly routable, so the target agent
must be on the same network as the runner to deliver the callback. For
production CI where the target is external, pass `--oob-url` to point at a
pre-configured, externally reachable listener instead.

## GitLab CI

```yaml
# .gitlab-ci.yml
batesian-scan:
  image: golang:1.26.9-bookworm
  stage: test
  script:
    - apt-get update && apt-get install -y --no-install-recommends jq
    - go install github.com/calbebop/batesian/cmd/batesian@main
    - batesian scan --target $AGENT_TARGET_URL --output json > batesian-results.json
    - |
      jq -e '
        .schema_version == 1 and
        .ruleset.selected > 0 and
        (.rule_outcomes | length) == .ruleset.selected and
        all(.rule_outcomes[]; .status == "findings" or .status == "no_findings") and
        ([.findings[] | select(.severity == "critical")] | length) == 0
      ' batesian-results.json
  artifacts:
    paths:
      - batesian-results.json
    when: always
  variables:
    AGENT_TARGET_URL: "https://agent.example.com"
```

## Jenkins (pipeline)

```groovy
stage('Agent Security Scan') {
    steps {
        sh 'go install github.com/calbebop/batesian/cmd/batesian@main'
        sh '''
            batesian scan \
              --target ${AGENT_TARGET_URL} \
              --output sarif \
              --timeout 30 \
              > batesian-results.sarif
        '''
        sh '''
            jq -e '
              (.runs | length) == 1 and
              (.runs[0].invocations | length) == 1 and
              (.runs[0].invocations[0] |
                .executionSuccessful == true and
                .properties.rulesSelected > 0 and
                .properties.rulesCompleted == .properties.rulesSelected and
                .properties.rulesSkipped == 0 and
                .properties.rulesErrored == 0)
            ' batesian-results.sarif
        '''
    }
    post {
        always {
            recordIssues(tool: sarif(pattern: 'batesian-results.sarif'))
        }
    }
}
```

The Jenkins agent needs Go 1.26.9 or newer and `jq` installed.
