package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// Reading only the first listed resource made the escalation to critical an
// accident of list order: a server that lists a public README ahead of its
// database credentials was reported as merely readable. The order is the
// server's choice, so it must not decide the severity.
//
// The harnesses below serve per-URI content, which the shared one in
// resources_unauth_test.go does not: it returns the same body for every read, so
// it cannot tell "read the first" from "read until something leaks".

// perURIResourceServer lists the given URIs and serves each one its own content.
// A URI present in contents is readable; any other listed URI is refused with a
// JSON-RPC error, which is how a real server denies one resource while serving
// its neighbours. reads counts resources/read calls received.
func perURIResourceServer(t *testing.T, uris []string, contents map[string]string) (*httptest.Server, *int) {
	t.Helper()

	reads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		method, _ := req["method"].(string)
		id := req["id"]
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "initialize":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"protocolVersion": "2025-03-26",
					"serverInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
					"capabilities":    map[string]interface{}{"resources": map[string]interface{}{}},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "resources/list":
			list := make([]map[string]interface{}, 0, len(uris))
			for _, u := range uris {
				list = append(list, map[string]interface{}{"uri": u, "name": u, "mimeType": "text/plain"})
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  map[string]interface{}{"resources": list},
			})
		case "resources/read":
			reads++
			params, _ := req["params"].(map[string]interface{})
			uri, _ := params["uri"].(string)
			text, readable := contents[uri]
			if !readable {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      id,
					"error":   map[string]interface{}{"code": -32002, "message": "Resource not found"},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"contents": []interface{}{
						map[string]interface{}{"uri": uri, "mimeType": "text/plain", "text": text},
					},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}))
	return srv, &reads
}

// A credential in a later resource must still escalate, and the finding must
// name that resource rather than the benign one that happened to be listed
// first.
func TestResourcesUnauth_CredentialInALaterResource(t *testing.T) {
	uris := []string{"config://readme", "config://app", "config://database"}
	contents := map[string]string{
		"config://readme":   "Welcome to the public configuration overview page.",
		"config://app":      `{"debug": false, "log_level": "info"}`,
		"config://database": "postgresql://admin:hunter2@db.internal:5432/prod",
	}

	ts, _ := perURIResourceServer(t, uris, contents)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (list + read), got %d", len(findings))
	}

	read := findings[1]
	if read.Severity != "critical" {
		t.Errorf("severity = %q, want critical: the third resource leaks a connection string", read.Severity)
	}
	if !strings.Contains(read.Title, "config://database") {
		t.Errorf("title should name the leaking resource, got %q", read.Title)
	}
	if !strings.Contains(read.Description, "Credential pattern detected") {
		t.Errorf("description should cite the matched pattern, got %q", read.Description)
	}
}

// Once a credential is found there is nothing stronger to look for, so the
// remaining budget is not spent.
func TestResourcesUnauth_StopsReadingOnceCredentialFound(t *testing.T) {
	uris := []string{"config://readme", "config://database", "config://extra1", "config://extra2"}
	contents := map[string]string{
		"config://readme":   "Public overview.",
		"config://database": "postgresql://admin:hunter2@db.internal:5432/prod",
		"config://extra1":   "more",
		"config://extra2":   "more",
	}

	ts, reads := perURIResourceServer(t, uris, contents)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	if _, err := exec.Execute(context.Background(), ts.URL, testOpts()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *reads != 2 {
		t.Errorf("reads = %d, want 2 (stop at the leaking resource)", *reads)
	}
}

// With nothing to escalate on, the behaviour is as before: the first readable
// resource is reported, at high.
func TestResourcesUnauth_NoCredentialAnywhereReportsFirst(t *testing.T) {
	uris := []string{"config://readme", "config://app"}
	contents := map[string]string{
		"config://readme": "Welcome to the public configuration overview page.",
		"config://app":    `{"debug": false, "log_level": "info"}`,
	}

	ts, _ := perURIResourceServer(t, uris, contents)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[1].Severity != "high" {
		t.Errorf("severity = %q, want high with no credential present", findings[1].Severity)
	}
	if !strings.Contains(findings[1].Title, "config://readme") {
		t.Errorf("title should name the first readable resource, got %q", findings[1].Title)
	}
}

// The cap bounds cost on a server that lists many resources, and the evidence
// has to say so: a bounded run must not read as an exhaustive one.
func TestResourcesUnauth_ReadsAreCappedAndTheCapIsReported(t *testing.T) {
	const listed = 12
	uris := make([]string, 0, listed)
	contents := map[string]string{}
	for i := 0; i < listed; i++ {
		u := fmt.Sprintf("config://item%d", i)
		uris = append(uris, u)
		contents[u] = "nothing sensitive here"
	}

	ts, reads := perURIResourceServer(t, uris, contents)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *reads != 5 {
		t.Errorf("reads = %d, want 5 (the cap)", *reads)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	want := fmt.Sprintf("resources examined: 5 of %d listed", listed)
	if !strings.Contains(findings[1].Evidence, want) {
		t.Errorf("evidence must state the bound, want %q in:\n%s", want, findings[1].Evidence)
	}
}

// A resource that cannot be read must not stop the search: the leak may be in
// the next one.
func TestResourcesUnauth_SkipsUnreadableResources(t *testing.T) {
	uris := []string{"config://denied", "config://database"}
	contents := map[string]string{
		"config://database": "postgresql://admin:hunter2@db.internal:5432/prod",
	}

	// config://denied is listed but absent from contents, so the server refuses
	// it with a JSON-RPC error while still serving the one after it.
	ts, _ := perURIResourceServer(t, uris, contents)
	defer ts.Close()

	exec := mcpattack.NewResourcesUnauthExecutor(resourcesRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[1].Severity != "critical" || !strings.Contains(findings[1].Title, "config://database") {
		t.Errorf("want critical finding for config://database, got %q at %q", findings[1].Title, findings[1].Severity)
	}
}
