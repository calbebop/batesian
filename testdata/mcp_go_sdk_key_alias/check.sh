#!/bin/sh
set -eu

export PATH="/usr/local/go/bin:$PATH"
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT INT TERM

(cd "$root" && go build -o "$tmp/batesian" ./cmd/batesian)

for version in v1.3.0 v1.4.0 v1.4.1; do
  mkdir "$tmp/$version"
  cp "$root/testdata/mcp_go_sdk_key_alias/server.go" "$tmp/$version/server.go"
  (
    cd "$tmp/$version"
    go mod init key-alias-fixture
    go get "github.com/modelcontextprotocol/go-sdk@$version"
    go mod tidy
    go build -o "$tmp/sdk-server" server.go
  )

  "$tmp/sdk-server" > "$tmp/server.log" 2>&1 &
  server_pid=$!
  ready=false
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    if curl -fsS http://127.0.0.1:7821/__calls > /dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  if [ "$ready" != true ]; then
    cat "$tmp/server.log"
    exit 1
  fi

  "$tmp/batesian" scan --target http://127.0.0.1:7821/mcp --protocol mcp \
    --rule-ids mcp-json-key-alias-001 --output json > "$tmp/result.json"
  python3 - "$version" "$tmp/result.json" <<'PY'
import json
import sys

version, path = sys.argv[1:]
with open(path, encoding="utf-8") as result_file:
    report = json.load(result_file)
expected = {
    "v1.3.0": ("case-folded", "findings"),
    "v1.4.0": ("NUL-suffixed", "findings"),
    "v1.4.1": (None, "no_findings"),
}
alias, status = expected[version]
findings = report["findings"]
outcomes = report["rule_outcomes"]
assert report["schema_version"] == 1
assert report["ruleset"]["selected"] == 1
assert not report["errors"] and not report["skipped"]
assert len(outcomes) == 1 and outcomes[0]["status"] == status
assert len(findings) == (0 if alias is None else 1)
if alias is not None:
    assert alias in findings[0]["title"]
    assert findings[0]["rule_id"] == "mcp-json-key-alias-001"
    assert findings[0]["severity"] == "low"
    assert findings[0]["confidence"] == "indicator"
    assert "sentinel" not in findings[0]["evidence"]
print(f"{version}: {status}" + (f" ({alias})" if alias else ""))
PY
  calls=$(curl -fsS http://127.0.0.1:7821/__calls)
  if [ "$calls" != 0 ]; then
    echo "$version: scanner invoked a tool" >&2
    exit 1
  fi
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=
done
