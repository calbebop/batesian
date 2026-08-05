//go:build integration

package mcp

import (
	"context"
	"os"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// The transport primitive was written from probing the official Python SDK, so
// this checks it against that SDK rather than only against a fixture that encodes
// the same understanding. It runs under the integration tag, alongside the era
// detection checks the weekly job already drives.
//
// Run it by hand with:
//
//	python testdata/mcp_modern_era_server.py &
//	BATESIAN_LIVE_MCP_ENDPOINT=http://127.0.0.1:7799/mcp \
//	  go test -tags=integration -run TestOpenSessions_Live ./internal/attack/mcp/

func TestOpenSessions_LiveDualEraServer(t *testing.T) {
	ep := os.Getenv(liveEndpointEnv)
	if ep == "" {
		t.Fatalf("%s must be set to the endpoint of a running modern-era server", liveEndpointEnv)
	}

	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 20}, attack.NewVars("", ""))
	sessions, err := openSessions(context.Background(), client, ep)
	if err != nil {
		t.Fatalf("openSessions: %v", err)
	}

	// The SDK serves both eras from one server, which is the case a rule that
	// only walked the first wire would half-test.
	if len(sessions) != 2 {
		t.Fatalf("expected both wires from an SDK server, got %d: %+v", len(sessions), sessions)
	}

	for _, s := range sessions {
		resp, err := s.post(context.Background(), client, 1, "tools/list", nil)
		if err != nil {
			t.Fatalf("%v tools/list: %v", s.Era, err)
		}
		if !resp.IsAccepted() {
			t.Fatalf("%v tools/list rejected by the SDK: %s", s.Era, resp.BodyString())
		}
		if !resp.ContainsAny(`"tools"`) {
			t.Errorf("%v tools/list returned no tools: %s", s.Era, resp.BodyString())
		}
	}
}
