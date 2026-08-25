package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func shadowRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-shadow-surface-001",
		Name:        "Shadow MCP Surface",
		Severity:    "high",
		Remediation: "Bind inspector processes to loopback behind authentication.",
	}
}

// withShadowPorts points the executor at the given ports for one test,
// restoring the documented list afterwards.
func withShadowPorts(t *testing.T, ports ...int) {
	t.Helper()
	old := mcp.ShadowPorts()
	mcp.SetShadowPorts(ports)
	t.Cleanup(func() { mcp.SetShadowPorts(old) })
}

// shadowMCPHandler models an inspector-style listener: an HTML page naming
// the product, and an MCP initialize that answers on any POST path. The
// foreignOriginRefused flag makes the Origin twin fail, as a hardened
// deployment would.
func shadowMCPHandler(foreignOriginRefused bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><title>MCP Inspector</title><body>proxy ready</body></html>"))
		case foreignOriginRefused && r.Header.Get("Origin") != "":
			http.Error(w, "forbidden origin", http.StatusForbidden)
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "inspector-proxy", "version": "1"},
				},
			})
		}
	}
}

func runShadow(t *testing.T, target string) ([]attack.Finding, error) {
	t.Helper()
	return mcp.NewShadowSurfaceExecutor(shadowRC()).Execute(context.Background(), target, attack.Options{TimeoutSeconds: 5})
}

// TestShadow_OpenWithOpenOriginFires: an unauthenticated MCP surface on an
// adjacent port that also accepts a foreign-Origin handshake is the full
// browser-reachable chain. MUST fire confirmed/high.
func TestShadow_OpenWithOpenOriginFires(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(shadowMCPHandler(false))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestShadow_HardenedOriginMedium: the surface is open but refuses the
// foreign-Origin twin. Rebinding is mitigated; the unauthenticated surface
// remains and reports medium.
func TestShadow_HardenedOriginMedium(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(shadowMCPHandler(true))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "medium" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want medium/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
}

// TestShadow_FingerprintOnlyLow: the page names a known product but no MCP
// endpoint answers. Low indicator, not silence - the dashboard is exposed
// even though its protocol could not be driven from here.
func TestShadow_FingerprintOnlyLow(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dashboard page on every path, protocol never answers: exactly the
		// "exposed product page, undriven control plane" posture.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><title>Serena Dashboard</title></html>"))
	}))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "low" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want low/RiskIndicator, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// TestShadow_NothingListeningClean: every probed port answers closed or with
// an unrelated service. Checked-and-absent is a genuine clean result here -
// each probe received an answer, so nothing went untested.
func TestShadow_NothingListeningClean(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	unrelated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>totally normal site</html>"))
	}))
	defer unrelated.Close()

	withShadowPorts(t, portOf(unrelated.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings with no shadow surfaces, got %d: %+v", len(findings), findings)
	}
}

// TestShadow_TargetPortSkipped: the port named in the target URL belongs to
// whatever rule owns that surface directly. The executor must not re-report
// it as a shadow discovery.
func TestShadow_TargetPortSkipped(t *testing.T) {
	main := httptest.NewServer(shadowMCPHandler(false))
	defer main.Close()

	withShadowPorts(t, portOf(main.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings: the target's own port must be skipped, got %d: %+v", len(findings), findings)
	}
}

func portOf(serverURL string) int {
	for i := len(serverURL) - 1; i >= 0; i-- {
		if serverURL[i] == ':' {
			out := 0
			for _, c := range serverURL[i+1:] {
				out = out*10 + int(c-'0')
			}
			return out
		}
	}
	panic("no port in " + serverURL)
}
