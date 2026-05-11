package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func TestTLSDowngrade_AcceptsHTTP(t *testing.T) {
	// HTTP server that accepts connections without redirecting to HTTPS.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".json") || r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name": "Test Agent", "version": "1.0", "url": "http://127.0.0.1/",
			})
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]interface{}{"code": -32601, "message": "method not found"},
			})
		}
	}))
	defer srv.Close()

	// Target already uses http:// so downgrade test should immediately find the open port.
	exec := a2aattack.NewTLSDowngradeExecutor(attack.RuleContext{ID: "a2a-tls-downgrade-001", Remediation: "use HTTPS"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for server that accepts plain HTTP")
	}
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("expected ConfirmedExploit, got %v", f.Confidence)
		}
		if f.Severity != "high" {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
	}
}

func TestTLSDowngrade_RedirectsToHTTPS(t *testing.T) {
	// Server responds with 301 redirect on HTTP -- correct behavior.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		https := "https://" + r.Host + r.URL.Path
		http.Redirect(w, r, https, http.StatusMovedPermanently)
	}))
	defer srv.Close()

	exec := a2aattack.NewTLSDowngradeExecutor(attack.RuleContext{ID: "a2a-tls-downgrade-001", Remediation: "use HTTPS"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for server that redirects to HTTPS, got %d", len(findings))
	}
}
