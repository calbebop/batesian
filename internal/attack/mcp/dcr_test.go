package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// Three rules register an OAuth client on the target and none of them removed it, so
// a scan against a server with open dynamic client registration left three behind
// permanently: one with an off-origin redirect_uri, one holding whatever privileged
// scopes the server would grant an anonymous registrant, and one whose metadata URLs
// point at an OOB listener that stops existing when the scan ends.
//
// RFC 7592 is the way back: a registration response may carry a
// registration_client_uri and a registration_access_token, and a DELETE to that URI
// with that token deregisters the client. These tests drive a server that implements
// it, and the ways a server can fail to.

// dcrServer is an authorization server with open registration. It records which
// clients exist so a test can assert the scan removed what it created.
type dcrServer struct {
	*httptest.Server
	mu sync.Mutex
	// live maps client_id to client_name for every registration not yet deleted.
	live map[string]string
	// deleteAuth records the Authorization header seen on each DELETE.
	deleteAuth []string
	// support toggles what the registration response advertises.
	support dcrSupport
	// grantedScope is echoed back so mcp-oauth-dcr-001 has something to report.
	grantedScope string
}

// dcrSupport describes how much of RFC 7592 the server implements.
type dcrSupport int

const (
	dcrFull       dcrSupport = iota // registration_client_uri + registration_access_token
	dcrNoneAtAll                    // neither: the client cannot be removed
	dcrNoToken                      // a URI but no token, so a delete would be unauthenticated
	dcrOffHostURI                   // a URI on another host, which must not be followed
	dcrRefuseDel                    // full advertisement, but DELETE is refused
)

func newDCRServer(t *testing.T, support dcrSupport, grantedScope string) *dcrServer {
	t.Helper()
	d := &dcrServer{live: map[string]string{}, support: support, grantedScope: grantedScope}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 base,
			"registration_endpoint":  base + "/register",
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
		})
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		name, _ := body["client_name"].(string)
		redirects, _ := body["redirect_uris"].([]interface{})

		d.mu.Lock()
		id := fmt.Sprintf("client-%d", len(d.live)+len(d.deleteAuth)+1)
		d.live[id] = name
		d.mu.Unlock()

		out := map[string]interface{}{"client_id": id, "client_name": name, "redirect_uris": redirects}
		if d.grantedScope != "" {
			out["scope"] = d.grantedScope
		}
		base := "http://" + r.Host
		switch d.support {
		case dcrFull, dcrRefuseDel:
			out["registration_client_uri"] = base + "/register/" + id
			out["registration_access_token"] = "rat-" + id
		case dcrNoToken:
			out["registration_client_uri"] = base + "/register/" + id
		case dcrOffHostURI:
			out["registration_client_uri"] = "http://elsewhere.invalid/register/" + id
			out["registration_access_token"] = "rat-" + id
		case dcrNoneAtAll:
			// Advertise nothing: an RFC 7591 server without the management protocol.
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/register/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/register/")
		d.mu.Lock()
		d.deleteAuth = append(d.deleteAuth, r.Header.Get("Authorization"))
		if d.support == dcrRefuseDel {
			d.mu.Unlock()
			w.WriteHeader(http.StatusForbidden)
			return
		}
		delete(d.live, id)
		d.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	// Enough of an MCP surface for the OAuth-gated rules to consider the target live.
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1,
			"error": map[string]interface{}{"code": -32000, "message": "authentication required"},
		})
	})

	d.Server = httptest.NewServer(mux)
	return d
}

// liveNames returns the client_names still registered.
func (d *dcrServer) liveNames() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.live))
	for _, n := range d.live {
		out = append(out, n)
	}
	return out
}

func (d *dcrServer) deletes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.deleteAuth...)
}

// The scope-escalation rule reads everything it needs out of the registration
// response, so the client it created must be gone by the time the rule returns.
func TestDCRCleanup_ScopeEscalationRemovesItsClient(t *testing.T) {
	srv := newDCRServer(t, dcrFull, "tools:write admin")
	defer srv.Close()

	exec := mcpattack.NewOAuthDCRExecutor(attack.RuleContext{ID: "mcp-oauth-dcr-001", Severity: "high"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the escalated-scope finding, got %d", len(findings))
	}
	if left := srv.liveNames(); len(left) != 0 {
		t.Errorf("the scan left %d client(s) registered: %v", len(left), left)
	}
	// RFC 7592 authenticates the delete with the registration access token, not with
	// the operator's credential.
	for _, auth := range srv.deletes() {
		if !strings.HasPrefix(auth, "Bearer rat-") {
			t.Errorf("delete should present the registration_access_token, got %q", auth)
		}
	}
	if !strings.Contains(findings[0].Evidence, "deleted afterwards via RFC 7592") {
		t.Errorf("the finding should record that the client was removed; got:\n%s", findings[0].Evidence)
	}
}

// A server without the management protocol keeps the client. That is not an error,
// but the operator has to be told, and told what to search for.
func TestDCRCleanup_NoManagementProtocolIsReported(t *testing.T) {
	srv := newDCRServer(t, dcrNoneAtAll, "tools:write admin")
	defer srv.Close()

	exec := mcpattack.NewOAuthDCRExecutor(attack.RuleContext{ID: "mcp-oauth-dcr-001", Severity: "high"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the escalated-scope finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if !strings.Contains(ev, "LEFT REGISTERED") {
		t.Errorf("a client that could not be removed must be reported as left behind; got:\n%s", ev)
	}
	if !strings.Contains(ev, "batesian-probe-") {
		t.Errorf("the report must name the client so it can be found by hand; got:\n%s", ev)
	}
	if !strings.Contains(ev, "RFC 7592") {
		t.Errorf("the reason should say what the server does not implement; got:\n%s", ev)
	}
}

// registration_client_uri is chosen by the TARGET. Following it to another host would
// let the target direct the scanner's requests, which is the same mistake as sending
// the operator's token off-host. It must be reported rather than followed.
func TestDCRCleanup_OffHostManagementURIIsNotFollowed(t *testing.T) {
	srv := newDCRServer(t, dcrOffHostURI, "tools:write admin")
	defer srv.Close()

	exec := mcpattack.NewOAuthDCRExecutor(attack.RuleContext{ID: "mcp-oauth-dcr-001", Severity: "high"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the escalated-scope finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if !strings.Contains(ev, "another host is not followed") {
		t.Errorf("an off-host management URI must be reported, not followed; got:\n%s", ev)
	}
	if !strings.Contains(ev, "elsewhere.invalid") {
		t.Errorf("the reason should name the host it declined to contact; got:\n%s", ev)
	}
}

// A server that advertises management and then refuses the delete has kept the
// client. The rule's verdict must not depend on cleanup either way.
func TestDCRCleanup_RefusedDeleteIsReportedNotFatal(t *testing.T) {
	srv := newDCRServer(t, dcrRefuseDel, "tools:write admin")
	defer srv.Close()

	exec := mcpattack.NewOAuthDCRExecutor(attack.RuleContext{ID: "mcp-oauth-dcr-001", Severity: "high"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("cleanup failure must not fail the rule: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the escalated-scope finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "refused with HTTP 403") {
		t.Errorf("the refusal should be reported with its status; got:\n%s", findings[0].Evidence)
	}
	if len(srv.deletes()) == 0 {
		t.Error("expected a delete to have been attempted")
	}
}

// A server with no token to authenticate the delete with cannot be cleaned up, and
// an unauthenticated delete must not be attempted.
func TestDCRCleanup_MissingAccessTokenIsNotDeletedBlind(t *testing.T) {
	srv := newDCRServer(t, dcrNoToken, "tools:write admin")
	defer srv.Close()

	exec := mcpattack.NewOAuthDCRExecutor(attack.RuleContext{ID: "mcp-oauth-dcr-001", Severity: "high"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the escalated-scope finding, got %d", len(findings))
	}
	if len(srv.deletes()) != 0 {
		t.Errorf("no delete should be sent without a registration_access_token, saw %d", len(srv.deletes()))
	}
	if !strings.Contains(findings[0].Evidence, "no registration_access_token") {
		t.Errorf("the reason should name the missing token; got:\n%s", findings[0].Evidence)
	}
}

// The confused-deputy rule uses its client_id for an authorize probe, so cleanup has
// to happen after that and still happen when the rule returns early.
func TestDCRCleanup_ConfusedDeputyRemovesItsClient(t *testing.T) {
	srv := newDCRServer(t, dcrFull, "")
	defer srv.Close()

	exec := mcpattack.NewConfusedDeputyExecutor(attack.RuleContext{
		ID: "mcp-confused-deputy-001", Severity: "high",
	})
	_, _ = exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})

	if left := srv.liveNames(); len(left) != 0 {
		t.Errorf("the confused-deputy probe left %d client(s) registered: %v", len(left), left)
	}
}

// A dry run must not register anything, so there is nothing to clean up and no
// cleanup request either.
func TestDCRCleanup_DryRunRegistersNothing(t *testing.T) {
	srv := newDCRServer(t, dcrFull, "tools:write admin")
	defer srv.Close()

	exec := mcpattack.NewOAuthDCRExecutor(attack.RuleContext{ID: "mcp-oauth-dcr-001", Severity: "high"})
	_, _ = exec.Execute(context.Background(), srv.URL, attack.Options{
		TimeoutSeconds: 5,
		DryRun:         true,
		Recorder:       &attack.Recorder{},
	})

	if left := srv.liveNames(); len(left) != 0 {
		t.Errorf("a dry run must send nothing, but %d client(s) were registered: %v", len(left), left)
	}
	if len(srv.deletes()) != 0 {
		t.Errorf("a dry run must send no delete either, saw %d", len(srv.deletes()))
	}
}
