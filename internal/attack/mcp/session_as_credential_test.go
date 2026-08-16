package mcp_test

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
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// sessionCredServer models how a server decides whether a tools/list call is
// authorized. mode picks the posture:
//
//	"session-authenticates": only an ISSUED session id is accepted   => the finding
//	"token-required":        every call needs the credential         => secure
//	"no-auth":               nothing is ever checked                 => suppressed
//	"session-presence-auth": ANY session id works without a token    => suppressed by
//	                         the never-issued control, because the issued id was not
//	                         what mattered
//	"sessionless-open":      no session at all works, unknown ids are refused =>
//	                         suppressed by the no-session control, because the call
//	                         did not need a session either
//	"no-auth-session-required": no authorization, but a session id is mandatory =>
//	                         suppressed by the anonymous-handshake control. This is
//	                         the official C# SDK's stateful sample.
//	"open-init-session-auth": initialize is UNGATED, and a session opened by a
//	                         credentialed caller then authorizes calls  => the
//	                         finding. An open handshake is not the same thing as no
//	                         authorization, and treating it as such suppressed this.
//	"open-init-no-anon-session": initialize is ungated but only a credentialed caller
//	                         is issued a session => suppressed, because with no
//	                         anonymous session to compare against a refusal cannot be
//	                         attributed to the missing credential.
//	"stateless":             no session id is ever issued            => not applicable
func sessionCredServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	const validToken = "operator-token"
	issued := map[string]bool{}
	// Which sessions were opened by a credentialed caller. Distinct from issued:
	// the postures where the handshake is ungated mint sessions for both callers,
	// and the whole question is whether the two are then treated alike.
	bornAuthed := map[string]bool{}
	minted := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		id := req["id"]
		sid := r.Header.Get("Mcp-Session-Id")
		authed := r.Header.Get("Authorization") == "Bearer "+validToken
		w.Header().Set("Content-Type", "application/json")

		result := func(v interface{}) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": v})
		}
		refuse := func() {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32001, "message": "Unauthorized"}})
		}

		switch method {
		case "initialize":
			switch mode {
			case "no-auth", "no-auth-session-required", "open-init-session-auth",
				"open-init-no-anon-session", "open-init-header-refuses":
				// Handshake is ungated in these postures.
			default:
				if !authed {
					refuse()
					return
				}
			}
			issueSession := mode != "stateless" &&
				(mode != "open-init-no-anon-session" || authed)
			if issueSession {
				minted++
				s := fmt.Sprintf("sess-%s-%d", mode, minted)
				issued[s] = true
				bornAuthed[s] = authed
				w.Header().Set("Mcp-Session-Id", s)
			}
			result(map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]interface{}{"name": "sc", "version": "1"},
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			ok := false
			switch mode {
			case "no-auth":
				ok = true
			case "no-auth-session-required":
				// The official C# SDK's stateful sample. No authorization anywhere, but
				// every non-initialize request must carry a session id the server issued.
				ok = issued[sid]
			case "session-presence-auth":
				// Presence of any session id is treated as authorization, so the
				// issued id is not what decided it. Isolates the never-issued control.
				ok = authed || sid != ""
			case "sessionless-open":
				// A call with no session is allowed; an unknown session id is refused
				// per the transport spec. Isolates the no-session control, and without
				// it step 5 would report a finding the session id did not cause.
				ok = authed || sid == "" || issued[sid]
			case "session-authenticates":
				ok = authed || issued[sid]
			case "open-init-session-auth", "open-init-no-anon-session":
				// The handshake is open, but the session remembers who opened it and
				// that memory is what authorizes the call.
				ok = authed || bornAuthed[sid]
			case "open-init-header-refuses":
				// The auth middleware rejects any request whose Authorization
				// header carries a token it does not recognize, even when the
				// session is valid. A request with no header but a valid session
				// is accepted. This models a server where the operator's stale
				// token makes the credentialed call fail while the session-only
				// path (the vulnerability) would succeed.
				if r.Header.Get("Authorization") != "" && !authed {
					refuse()
					return
				}
				ok = authed || issued[sid]
			default: // token-required, stateless
				ok = authed
			}
			if !ok {
				refuse()
				return
			}
			result(map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "echo"}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"}})
		}
	}))
}

func runSessionCred(t *testing.T, srv *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	exec := mcpattack.NewSessionAsCredentialExecutor(attack.RuleContext{ID: "mcp-session-as-credential-001"})
	return exec.Execute(context.Background(), srv.URL, attack.Options{
		TimeoutSeconds: 5, Token: "operator-token",
	})
}

// The finding: a request carrying no credential is answered because it presents a
// session id the server issued, while the same request with a never-issued id is
// refused. The session id alone authorized the call.
func TestSessionAsCredential_Vulnerable(t *testing.T) {
	srv := sessionCredServer(t, "session-authenticates")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %s/%s", f.Severity, f.Confidence)
	}
	// The evidence has to show both controls, or the claim is not supported.
	for _, want := range []string{
		"with no session and no credential: refused",
		"never-issued session id",
		"NO credential: answered",
	} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("evidence missing %q; got:\n%s", want, f.Evidence)
		}
	}
}

// Every call needs the credential. The session id carries no authority.
func TestSessionAsCredential_TokenRequiredIsSecure(t *testing.T) {
	srv := sessionCredServer(t, "token-required")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("a server that checks the credential on every call is secure, got %d findings", len(findings))
	}
}

// A server with no authorization anywhere is mcp-tools-unauth-001's finding. The
// MUST NOT binds only on servers that implement authorization, so this rule must
// not claim it.
func TestSessionAsCredential_NoAuthIsSuppressed(t *testing.T) {
	srv := sessionCredServer(t, "no-auth")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("no authorization anywhere is a different rule's finding, got %d", len(findings))
	}
}

// A server that accepts ANY session id is not authenticating by the identity of the
// session, it is treating presence of the header as authorization. Step 5 would
// succeed there too, so without the never-issued control the rule would claim the
// issued session id was what authorized the call when any string would have done.
func TestSessionAsCredential_AnySessionIDIsSuppressed(t *testing.T) {
	srv := sessionCredServer(t, "session-presence-auth")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("a server that ignores session ids must not be reported, got %d", len(findings))
	}
}

// No session id means nothing to misuse. 2026-07-28 removed protocol-level
// sessions, so this is also how the rule behaves on that revision.
func TestSessionAsCredential_StatelessIsNotApplicable(t *testing.T) {
	srv := sessionCredServer(t, "stateless")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("a stateless server has no session id to misuse, got %d", len(findings))
	}
}

// Without a credential the rule cannot establish a session to strip one from, so
// it has nothing to compare and must say so rather than report clean.
func TestSessionAsCredential_NoCredentialIsInconclusive(t *testing.T) {
	srv := sessionCredServer(t, "session-authenticates")
	defer srv.Close()

	exec := mcpattack.NewSessionAsCredentialExecutor(attack.RuleContext{ID: "mcp-session-as-credential-001"})
	findings, err := exec.Execute(context.Background(), srv.URL, attack.Options{TimeoutSeconds: 5})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want ErrInconclusive without a credential, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// A server that allows a call with no session at all, while refusing session ids it
// never issued, is simply open on that surface. Without the no-session control the
// never-issued probe would be refused, step 5 would be answered, and the rule would
// report a finding the session id did not cause.
func TestSessionAsCredential_SessionlessOpenIsSuppressed(t *testing.T) {
	srv := sessionCredServer(t, "sessionless-open")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("the call did not need a session, so the session id authorized nothing; got %d findings",
			len(findings))
	}
}

// The false positive this rule shipped with in development, caught against the
// official MCP C# SDK's stateful sample rather than in a unit test.
//
// That server has no authorization at all, and requires a session id on every
// non-initialize request. So a call with no session is refused, and a call with a
// never-issued session is refused, both for SESSION reasons rather than credential
// reasons. Those controls cannot tell the two apart, every one of them passed, and
// the final probe succeeded because nothing is ever authenticated. Establishing
// that the server implements authorization at all, by attempting an ANONYMOUS
// handshake, is what separates the two.
func TestSessionAsCredential_NoAuthButSessionRequiredIsSuppressed(t *testing.T) {
	srv := sessionCredServer(t, "no-auth-session-required")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("this server authenticates nothing, so the session id authorized nothing; "+
			"got %d finding(s)", len(findings))
	}
}

// An ungated handshake is not the same thing as no authorization. This server
// lets anyone call initialize, but a session opened by a credentialed caller is
// what authorizes the calls that follow, which is precisely the failure the rule
// tests for. Reading "initialize answered anonymously" as "implements no
// authorization" suppressed it.
//
// The oracle here is stronger than the never-issued-id control: both session ids
// were minted by this server, and the only difference between them is whether a
// credential was presented when they were opened.
func TestSessionAsCredential_OpenHandshakeStillFires(t *testing.T) {
	srv := sessionCredServer(t, "open-init-session-auth")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Evidence, "ANONYMOUS handshake") {
		t.Errorf("evidence should name the anonymous session it was compared against; got:\n%s",
			findings[0].Evidence)
	}
}

// The handshake is open but only a credentialed caller is issued a session, so
// there is no anonymous session to compare against. The refusals below could be
// about the missing session rather than the missing credential, and that is the
// ambiguity that produced the C# SDK false positive. Report nothing.
func TestSessionAsCredential_NoAnonymousSessionIsSuppressed(t *testing.T) {
	srv := sessionCredServer(t, "open-init-no-anon-session")
	defer srv.Close()

	findings, err := runSessionCred(t, srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("no anonymous session was available to attribute the refusals to the "+
			"missing credential; got %d finding(s)", len(findings))
	}
}

// TestSessionAsCredential_RefusedCredentialNotClean: the operator's token is
// rejected on the credentialed tools/list (stale, wrong scope). The rule used
// to report clean, claiming the server was tested when the premise (the
// credential works) was never established. It must report not-tested instead.
func TestSessionAsCredential_RefusedCredentialNotClean(t *testing.T) {
	srv := sessionCredServer(t, "open-init-header-refuses")
	defer srv.Close()

	exec := mcpattack.NewSessionAsCredentialExecutor(attack.RuleContext{ID: "mcp-session-as-credential-001"})
	_, err := exec.Execute(context.Background(), srv.URL, attack.Options{
		TimeoutSeconds: 5, Token: "stale-token",
	})
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("a refused credentialed call must report not-tested, not clean; "+
			"want ErrInconclusive, got %v", err)
	}
}
