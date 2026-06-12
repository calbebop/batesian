# CI/CD Integration

Batesian outputs SARIF, which GitHub natively ingests as Code Scanning alerts.
Integrating into CI takes two lines on top of the scan command.

## GitHub Actions

### Basic scan -- fail on high+ findings

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
      security-events: write   # Required to upload SARIF to Code Scanning

    steps:
      - uses: actions/checkout@v4

      - name: Install Batesian
        run: go install github.com/calbebop/batesian/cmd/batesian@latest

      - name: Run scan (SARIF output)
        run: |
          batesian scan \
            --target ${{ vars.AGENT_TARGET_URL }} \
            --output sarif \
            --timeout 30 \
            > results.sarif
        env:
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
```

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

The push-notification SSRF rule (`a2a-push-ssrf-001`) requires an
out-of-band callback listener. In CI, start the OOB listener with `--oob`:

```yaml
      - name: Run scan with OOB listener
        run: |
          batesian scan \
            --target ${{ vars.AGENT_TARGET_URL }} \
            --oob \
            --output sarif \
            > results.sarif
```

The `--oob` flag starts a local HTTP listener on a random port and derives the
callback URL from the host's detected outbound interface IP (typically a private
or RFC 1918 address). On GitHub Actions runners, this IP is not publicly
routable, so the target agent must be on the same network as the runner to
receive the callback. For production CI where the target is external, use
`--oob-url` to point to a pre-configured externally reachable listener instead.

## GitLab CI

```yaml
# .gitlab-ci.yml
batesian-scan:
  image: golang:1.25
  stage: test
  script:
    - go install github.com/calbebop/batesian/cmd/batesian@latest
    - batesian scan --target $AGENT_TARGET_URL --output json > batesian-results.json
    - |
      jq -e '(.findings // []) | map(select(.severity == "critical")) | length == 0' \
        batesian-results.json
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
        sh 'go install github.com/calbebop/batesian/cmd/batesian@latest'
        sh '''
            batesian scan \
              --target ${AGENT_TARGET_URL} \
              --output sarif \
              --timeout 30 \
              > batesian-results.sarif
        '''
    }
    post {
        always {
            recordIssues(tool: sarif(pattern: 'batesian-results.sarif'))
        }
    }
}
```
