//go:build integration

package mcp

import (
	"context"
	"os"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// Era detection was written from the specification, before any implementation
// spoke the 2026-07-28 revision. This test checks it against a real one.
//
// It is behind the integration tag because it needs a server the normal suite
// cannot start: the MCP Python SDK v2, launched from
// testdata/mcp_modern_era_server.py. The weekly workflow starts that server and
// runs this; nothing here runs in the ordinary CI gate.
//
// Run it by hand with:
//
//	python testdata/mcp_modern_era_server.py &
//	BATESIAN_LIVE_MCP_ENDPOINT=http://127.0.0.1:7799/mcp \
//	  go test -tags=integration -run TestDetectEra_Live ./internal/attack/mcp/

const liveEndpointEnv = "BATESIAN_LIVE_MCP_ENDPOINT"

func liveEndpoint(t *testing.T) string {
	t.Helper()
	ep := os.Getenv(liveEndpointEnv)
	if ep == "" {
		// Fail rather than skip. A silent skip would let the workflow go green
		// while testing nothing, which is the failure mode this whole job
		// exists to avoid.
		t.Fatalf("%s must be set to the endpoint of a running modern-era server", liveEndpointEnv)
	}
	return ep
}

func liveClient() *attack.HTTPClient {
	opts := attack.Options{TimeoutSeconds: 20}
	return attack.NewUnauthHTTPClient(opts, attack.NewVars("", ""))
}

// A server whose server/discover reply advertises the modern revision must be
// classified modern. Detection reads that reply's supportedVersions rather than
// the fact that it answered, so if the specification or the SDK changes the shape
// of the field, this is where we find out.
func TestDetectEra_LiveModernServer(t *testing.T) {
	ep := liveEndpoint(t)

	if era := detectEra(context.Background(), liveClient(), ep); era != EraModern {
		t.Fatalf("detectEra(%s) = %v, want modern", ep, era)
	}
}

// The same process also serves the 2025-era handshake, which is what the SDK
// does by default and therefore what a real deployment looks like. The legacy
// rules must still be able to open a session against it, because that is the
// reason modern-era rule work is not urgent: current servers still answer the
// handshake these rules are built on.
func TestInitializeMCP_LiveModernServerStillHandshakes(t *testing.T) {
	ep := liveEndpoint(t)

	session, err := initializeMCP(context.Background(), liveClient(), ep)
	if err != nil {
		t.Fatalf("initializeMCP(%s): %v, want a legacy session from a dual-era server", ep, err)
	}
	if session.Endpoint == "" {
		t.Error("session carries no endpoint")
	}
	if session.ProtocolVersion == "" {
		t.Error("session carries no negotiated protocol version")
	}
}
