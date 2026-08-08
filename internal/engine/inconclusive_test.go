package engine_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	batesian "github.com/calbebop/batesian"
	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

// TestRun_UnreachableA2ARuleIsInconclusive verifies that an A2A rule run against
// an unreachable target is recorded as a skipped/inconclusive result (the
// executor returned attack.ErrInconclusive), not as a clean pass or an error.
func TestRun_UnreachableA2ARuleIsInconclusive(t *testing.T) {
	loaded, _, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	var r *rules.Rule
	for _, x := range loaded {
		if x.ID == "a2a-peer-impersonation-001" {
			r = x
			break
		}
	}
	if r == nil {
		t.Skip("a2a-peer-impersonation-001 not present")
	}

	res := engine.New(attack.Options{TimeoutSeconds: 1}).Run(t.Context(), "http://127.0.0.1:1", []*rules.Rule{r})[0]
	if !res.Skipped || !strings.Contains(res.SkipMsg, "could not reach") {
		t.Errorf("expected inconclusive skip, got skipped=%v msg=%q err=%v findings=%d",
			res.Skipped, res.SkipMsg, res.Err, len(res.Findings))
	}
}

// TestRun_ModernEraServerReportsUnsupportedProtocol verifies the end-to-end
// path: an MCP rule pointed at a stateless (2026-07-28) server is skipped with a
// message naming the protocol era, not with a bare "could not reach". The
// distinction matters to an operator, who would otherwise assume a network fault
// when the real cause is that these rules do not speak the server's version.
func TestRun_ModernEraServerReportsUnsupportedProtocol(t *testing.T) {
	// A modern server: it has no initialize method, and answers the era probe
	// with a spec-reserved error code.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32022,` +
			`"message":"Unsupported protocol version","data":{"supported":["2026-07-28"]}}}`))
	}))
	defer srv.Close()

	loaded, _, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	var r *rules.Rule
	for _, x := range loaded {
		if x.ID == "mcp-tools-unauth-001" {
			r = x
			break
		}
	}
	if r == nil {
		t.Skip("mcp-tools-unauth-001 not present")
	}

	res := engine.New(attack.Options{TimeoutSeconds: 5}).Run(t.Context(), srv.URL, []*rules.Rule{r})[0]
	if !res.Skipped {
		t.Fatalf("expected a skipped result, got skipped=%v err=%v findings=%d", res.Skipped, res.Err, len(res.Findings))
	}
	// A supplied reason replaces the generic sentence rather than being appended to
	// it. This server was reached and answered; claiming it could not be reached is
	// the network-fault misdirection this test's premise is about.
	if strings.Contains(res.SkipMsg, "could not reach") {
		t.Errorf("skip message claims the target was unreachable, but it answered the era probe: %q", res.SkipMsg)
	}
	// And the actionable detail is present.
	if !strings.Contains(res.SkipMsg, "2026-07-28") {
		t.Errorf("skip message should name the unsupported protocol era, got %q", res.SkipMsg)
	}
}
