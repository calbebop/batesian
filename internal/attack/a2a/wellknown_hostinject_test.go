package a2a_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func hostInjectCard(url string) map[string]interface{} {
	return map[string]interface{}{
		"name":               "Test Agent",
		"description":        "Test agent",
		"version":            "0.3.0",
		"url":                url,
		"capabilities":       map[string]interface{}{},
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"skills":             []interface{}{},
	}
}

func hostInjectModernCard(url string) map[string]interface{} {
	card := hostInjectCard(url)
	delete(card, "url")
	card["version"] = "1.0.0"
	card["supportedInterfaces"] = []map[string]string{{
		"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
	}}
	card["skills"] = []map[string]interface{}{{
		"id": "test", "name": "Test", "description": "Test skill", "tags": []string{"test"},
	}}
	return card
}

func TestWellKnownHostInject_XForwardedHostReflected(t *testing.T) {
	// Server reflects X-Forwarded-Host into the agent card url field.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		card := hostInjectModernCard("http://" + host + "/")
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
		card := hostInjectCard("https://agent.example.com/")
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

func TestWellKnownHostInject_UnobservedProbeOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		reason string
	}{
		{"server error", http.StatusServiceUnavailable, "", "HTTP 503"},
		{"request timeout", http.StatusRequestTimeout, "", "HTTP 408"},
		{"rate limited", http.StatusTooManyRequests, "", "HTTP 429"},
		{"malformed JSON", http.StatusOK, "{", "invalid card JSON"},
		{"non-card JSON", http.StatusOK, `{"status":"ok"}`, "invalid Agent Card"},
		{"partial card", http.StatusOK, `{"name":"Agent"}`, "invalid Agent Card"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/agent-card.json" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.Header.Get("X-Original-Host") != "" {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
					return
				}
				_ = json.NewEncoder(w).Encode(hostInjectCard("https://agent.example.com/"))
			}))
			defer srv.Close()

			exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
			findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) || !strings.Contains(err.Error(), "X-Original-Host: "+tc.reason) {
				t.Fatalf("want incomplete X-Original-Host probe, got findings=%v err=%v", findings, err)
			}
		})
	}
}

func TestWellKnownHostInject_HeaderRejectionIsObserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/agent-card.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Original-Host") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(hostInjectCard("https://agent.example.com/"))
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil || len(findings) != 0 {
		t.Fatalf("want clean result for rejected header and absent legacy path, got findings=%v err=%v", findings, err)
	}
}

func TestWellKnownHostInject_PartialFindingNotesUnobservedProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/agent-card.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Original-Host") != "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = "agent.example.com"
		}
		_ = json.NewEncoder(w).Encode(hostInjectCard("https://" + host + "/"))
	}))
	defer srv.Close()

	exec := a2aattack.NewWellKnownHostInjectExecutor(attack.RuleContext{ID: "a2a-wellknown-hostinject-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil || len(findings) == 0 {
		t.Fatalf("want reflection finding, got findings=%v err=%v", findings, err)
	}
	if !strings.Contains(findings[0].Evidence, "X-Original-Host: HTTP 503") {
		t.Fatalf("finding omitted unobserved probe: %q", findings[0].Evidence)
	}
}

// TestWellKnownHostInject_HostHeaderReflected verifies the forged Host header
// actually reaches the server (req.Host plumbing) and a reflection into the url
// field is reported as a high/RiskIndicator (reflection is proven; the
// attacker-influences-header precondition is not).
func TestWellKnownHostInject_HostHeaderReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only trusts the real Host header (not X-Forwarded-*).
		card := hostInjectCard("http://" + r.Host + "/")
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
		card := hostInjectCard("https://agent.example.com/")
		card["description"] = "Operated from origin " + host
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
		card := hostInjectCard(fmt.Sprintf("http://%s/api", host))
		card["provider"] = map[string]interface{}{
			"organization": "Acme",
			"url":          fmt.Sprintf("https://%s/company", host),
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
		card := hostInjectCard("https://" + host + "/a2a")
		card["provider"] = map[string]interface{}{"organization": "Org", "url": "https://" + host + "/org"}
		_ = json.NewEncoder(w).Encode(card)
	}))
}

// Repeated scans must agree and report each header only once.
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
