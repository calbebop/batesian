package a2a_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func TestWellKnownHostInject_XForwardedHostReflected(t *testing.T) {
	// Server reflects X-Forwarded-Host into the agent card url field.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		card := map[string]interface{}{
			"name":    "Test Agent",
			"version": "1.0",
			"url":     "http://" + host + "/",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for server that reflects X-Forwarded-Host")
	}
	for _, f := range findings {
		if f.Severity != "high" {
			t.Errorf("expected high severity, got %s", f.Severity)
		}
		if f.Confidence != attack.RiskIndicator {
			t.Errorf("expected RiskIndicator, got %v", f.Confidence)
		}
	}
}

func TestWellKnownHostInject_HardcodedURL(t *testing.T) {
	// Server always returns the same hardcoded URL - not vulnerable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		card := map[string]interface{}{
			"name":    "Secure Agent",
			"version": "1.0",
			"url":     "https://agent.example.com/",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for hardcoded URL, got %d", len(findings))
	}
}

// TestWellKnownHostInject_HostHeaderReflected verifies the forged Host header
// actually reaches the server (req.Host plumbing) and a reflection into the url
// field is reported as a high/RiskIndicator (reflection is proven; the
// attacker-influences-header precondition is not).
func TestWellKnownHostInject_HostHeaderReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only trusts the real Host header (not X-Forwarded-*).
		card := map[string]interface{}{
			"name":    "Host-Reflect Agent",
			"version": "1.0",
			"url":     "http://" + r.Host + "/",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding when the forged Host header is reflected into url")
	}
	if findings[0].Severity != "high" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected high/RiskIndicator, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// TestWellKnownHostInject_NonURLFieldReflected verifies that reflection into a
// non-URL field (description) is downgraded to medium/RiskIndicator.
func TestWellKnownHostInject_NonURLFieldReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = "static-host"
		}
		card := map[string]interface{}{
			"name":        "Desc-Reflect Agent",
			"version":     "1.0",
			"url":         "https://agent.example.com/", // hardcoded, safe
			"description": "Operated from origin " + host,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding for non-URL reflection")
	}
	for _, f := range findings {
		if f.Severity != "medium" || f.Confidence != attack.RiskIndicator {
			t.Errorf("expected medium/RiskIndicator for non-URL reflection, got %q/%q (%s)",
				f.Severity, f.Confidence, f.Title)
		}
	}
}

func TestWellKnownHostInject_ReflectsInProviderField(t *testing.T) {
	// Server reflects X-Original-Host into both url and provider.url.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Original-Host")
		if host == "" {
			host = "static.example.com"
		}
		card := map[string]interface{}{
			"name":    "Multi-Reflect Agent",
			"version": "1.0",
			"url":     fmt.Sprintf("http://%s/api", host),
			"provider": map[string]interface{}{
				"organization": "Acme",
				"url":          fmt.Sprintf("https://%s/company", host),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(card)
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for server that reflects X-Original-Host")
	}
}

// multiFieldReflectingServer reflects the injected host into TWO url-ish fields and
// serves both well-known paths, which is what makes the ordering matter: the same
// header is probed twice, once per path, and the dedup key is built by joining the
// reflected field names.
func multiFieldReflectingServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/agent-card.json" && r.URL.Path != "/.well-known/agent.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"name":         "Reflector",
			"description":  "d",
			"version":      "1.0.0",
			"url":          "https://" + host + "/a2a",
			"provider":     map[string]interface{}{"organization": "Org", "url": "https://" + host + "/org"},
			"capabilities": map[string]interface{}{},
			"skills":       []interface{}{},
		})
	}))
}

// Two scans of an unchanged target must agree, and each header must be reported
// once rather than once per field ordering.
//
// findReflections walks the card with a map range, and Go randomizes map iteration
// order. The reflected field names flow into the dedup key that collapses the same
// reflection across the two well-known paths, so before the paths were sorted the
// key differed between runs: the same header was reported twice, once as
// "provider.url, url" and once as "url, provider.url", and this server yielded 3, 4
// or 5 findings on identical input. Repeating the scan is what makes the failure
// reliable instead of a coin flip.
func TestWellKnownHostInject_ResultIsDeterministic(t *testing.T) {
	srv := multiFieldReflectingServer(t)
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})

	var first []string
	for run := 0; run < 12; run++ {
		findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
		if err != nil {
			t.Fatalf("run %d: unexpected error: %v", run, err)
		}

		titles := make([]string, 0, len(findings))
		for _, f := range findings {
			titles = append(titles, f.Title)
		}

		// No header may appear twice: two findings differing only in field order
		// are the same reflection reported once per ordering.
		perHeader := map[string]int{}
		for _, f := range findings {
			for _, h := range []string{"Host", "X-Forwarded-Host", "X-Original-Host", "X-Forwarded-For"} {
				if strings.Contains(f.Title, `"`+h+`"`) {
					perHeader[h]++
				}
			}
		}
		for h, n := range perHeader {
			if n > 1 {
				t.Fatalf("run %d: header %s reported %d times; the same reflection must dedupe across both well-known paths: %v",
					run, h, n, titles)
			}
		}

		if run == 0 {
			first = titles
			continue
		}
		if len(titles) != len(first) {
			t.Fatalf("run %d produced %d finding(s), run 0 produced %d: identical input must give identical output; first=%v now=%v",
				run, len(titles), len(first), first, titles)
		}
		for i := range titles {
			if titles[i] != first[i] {
				t.Fatalf("run %d finding %d differs from run 0: first=%q now=%q", run, i, first[i], titles[i])
			}
		}
	}
}
