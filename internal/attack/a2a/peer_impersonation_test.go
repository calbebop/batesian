package a2a_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	a2aattack "github.com/calbebop/batesian/internal/attack/a2a"
)

func peerImpersonationRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "a2a-peer-impersonation-001",
		Name:        "A2A Peer Agent Impersonation via Forged JWT",
		Severity:    "high",
		Remediation: "Validate JWT signatures against a known JWKS endpoint.",
	}
}

// jwtAcceptingServer accepts any request that includes an Authorization header
// and rejects requests without one. This simulates a server that reads JWT
// claims without verifying the signature.
func jwtAcceptingServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, map[string]interface{}{
				"name":    "test-agent",
				"version": "1.0",
			})
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"id":     "task-001",
				"status": map[string]interface{}{"state": "completed"},
			},
		})
	}))
}

// unauthAllowedServer accepts all requests regardless of whether a token is present.
func unauthAllowedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, map[string]interface{}{
				"name":    "open-agent",
				"version": "1.0",
			})
			return
		}
		req := readBody(r)
		id := req["id"]
		if req["method"] == "GetTask" || req["method"] == "tasks/get" {
			rpcErr(w, id, -32001, "Task not found")
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"result": map[string]interface{}{
				"id":     "task-002",
				"status": map[string]interface{}{"state": "completed"},
			},
		})
	}))
}

// testIssuer is the issuer the fixtures below publish in their agent card. The
// rule must send it in the forged token, or an issuer-filtering server refuses on
// the wrong claim and the missing signature check is never reached.
const testIssuer = "https://sso.example.test/realms/agents"

// cardWithIssuer is an agent card that publishes testIssuer the way a real
// OIDC-protected agent does.
func cardWithIssuer(name string) map[string]interface{} {
	return map[string]interface{}{
		"name":    name,
		"version": "1.0",
		"securitySchemes": map[string]interface{}{
			"sso": map[string]interface{}{
				"type":             "openIdConnect",
				"openIdConnectUrl": testIssuer + "/.well-known/openid-configuration",
			},
		},
	}
}

// properJWTServer publishes its issuer and still rejects every bearer token, which
// is what real signature validation looks like: the forged token carries the right
// issuer and is refused anyway, because the random signing key is unknown.
//
// It has to publish the issuer for the test to mean anything. A server that
// publishes nothing and refuses everything is indistinguishable from one that
// filters unknown issuers without checking signatures, which is what
// TestPeerImpersonation_NoPublishedIssuerIsInconclusive covers.
func properJWTServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, cardWithIssuer("secure-agent"))
			return
		}
		// Any bearer token is rejected; the forged token (random key) will fail.
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

// opaqueServer publishes no card and no issuer, and refuses everything. Whether it
// verifies signatures cannot be determined from outside.
func opaqueServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
}

// issuerAllowlistServer is the failure this rule exists to catch, in the shape
// that used to escape it: the issuer is checked against the published value and
// the signature is never verified at all. Unauthenticated callers are refused, so
// the baseline probe behaves exactly as it does on a secure server.
func issuerAllowlistServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, cardWithIssuer("billing-orchestrator"))
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Decode the claims without verifying anything, and trust the issuer.
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var claims struct {
			Iss string `json:"iss"`
		}
		if json.Unmarshal(raw, &claims) != nil || claims.Iss != testIssuer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"id":     "task-003",
				"status": map[string]interface{}{"state": "completed"},
			},
		})
	}))
}

// TestPeerImpersonation_ForgedJWTAccepted verifies a high-severity finding is
// emitted when the server accepts a forged JWT but rejects unauthenticated requests.
func TestPeerImpersonation_ForgedJWTAccepted(t *testing.T) {
	ts := jwtAcceptingServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on JWT-accepting server, got none")
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high severity, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected ConfirmedExploit confidence, got %q", findings[0].Confidence)
	}
	if !strings.Contains(findings[0].Description, "does not establish") {
		t.Errorf("finding must qualify unobserved peer privileges: %s", findings[0].Description)
	}
}

// TestPeerImpersonation_UnauthAllowed verifies a medium-severity finding is
// emitted when the server accepts requests without any authentication.
func TestPeerImpersonation_UnauthAllowed(t *testing.T) {
	ts := unauthAllowedServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings on unauthenticated-allow server, got none")
	}
	if findings[0].Severity != "medium" {
		t.Errorf("expected medium severity, got %q", findings[0].Severity)
	}
	if findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("expected RiskIndicator confidence, got %q", findings[0].Confidence)
	}
	if strings.Contains(findings[0].Title, "impersonation") {
		t.Errorf("anonymous access does not prove impersonation: %s", findings[0].Title)
	}
}

// jwtAcceptingRPCErrorServer accepts requests with an Authorization header but
// rejects unauthenticated ones with HTTP 200 carrying a JSON-RPC error envelope
// (rather than a 401/403). This is the false-negative case the broadened
// rejection oracle (!baselineOK) is meant to catch.
func jwtAcceptingRPCErrorServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, map[string]interface{}{"name": "rpc-agent", "version": "1.0"})
			return
		}
		id := readBody(r)["id"]
		if r.Header.Get("Authorization") == "" {
			// HTTP 200 but a JSON-RPC error => rejection at the protocol layer.
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32001, "message": "unauthorized"},
			})
			return
		}
		writeJSON(w, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"result":  map[string]interface{}{"id": "task-003", "status": map[string]interface{}{"state": "completed"}},
		})
	}))
}

// TestPeerImpersonation_ForgedAcceptedRPCErrorBaseline verifies the forged-JWT
// finding still fires when the unauthenticated baseline is rejected via a
// JSON-RPC error envelope instead of an HTTP 401/403.
func TestPeerImpersonation_ForgedAcceptedRPCErrorBaseline(t *testing.T) {
	ts := jwtAcceptingRPCErrorServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding when baseline is rejected via JSON-RPC error, got none")
	}
	if findings[0].Severity != "high" || findings[0].Confidence != attack.ConfirmedExploit {
		t.Errorf("expected high/ConfirmedExploit, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

// TestPeerImpersonation_ProperValidation verifies no finding is emitted when the
// server rejects all tokens (forged or absent), indicating real signature checks.
func TestPeerImpersonation_ProperValidation(t *testing.T) {
	ts := properJWTServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on secure server, got %d: %v", len(findings), findings)
	}
}

// TestPeerImpersonation_IssuerAllowlistOnly is the regression test for the false
// negative this rule shipped with. The server trusts the issuer it publishes and
// never verifies a signature, so any caller can mint a token for any subject. With
// a fabricated issuer the forged probe was refused on the wrong claim and the rule
// reported the server clean.
func TestPeerImpersonation_IssuerAllowlistOnly(t *testing.T) {
	ts := issuerAllowlistServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding: the server accepts a randomly signed token bearing its published issuer")
	}
	if findings[0].Severity != "high" {
		t.Errorf("expected high severity, got %q", findings[0].Severity)
	}
	// The evidence must show the issuer was taken from the target, not invented,
	// because that is what makes the acceptance meaningful.
	if !strings.Contains(findings[0].Evidence, testIssuer) {
		t.Errorf("evidence should record the discovered issuer, got: %s", findings[0].Evidence)
	}
	if !strings.Contains(findings[0].Evidence, "securityScheme") {
		t.Errorf("evidence should name where the issuer came from, got: %s", findings[0].Evidence)
	}
}

// TestPeerImpersonation_NoPublishedIssuerIsInconclusive: a server that publishes no
// issuer and refuses everything cannot be assessed. Reporting it clean would claim
// signature verification that was never demonstrated, since refusing a token with
// an invented issuer is what an issuer filter does too.
func TestPeerImpersonation_NoPublishedIssuerIsInconclusive(t *testing.T) {
	ts := opaqueServer(t)
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive when no issuer is discoverable, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
	// The reason must name the actual obstacle, not a network problem.
	if !strings.Contains(err.Error(), "no trusted issuer") {
		t.Errorf("inconclusive reason should explain the missing issuer, got: %v", err)
	}
}

// TestPeerImpersonation_NotA2AServer verifies that against a server that returns
// 404 for all requests (no reachable A2A endpoint) the rule reports inconclusive
// rather than a (misleading) clean result.
func TestPeerImpersonation_NotA2AServer(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive on non-A2A server, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings on non-A2A server, got %d", len(findings))
	}
}

// v03IssuerAllowlistServer answers the v1.0 method with -32601.
func v03IssuerAllowlistServer(t *testing.T, methodStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, cardWithIssuer("v03-agent"))
			return
		}
		var req struct {
			Method string      `json:"method"`
			ID     interface{} `json:"id"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if req.Method == "GetTask" || req.Method == "tasks/get" {
			rpcErr(w, req.ID, -32001, "Task not found")
			return
		}
		if req.Method != "message/send" {
			// This revision does not define that name.
			w.WriteHeader(methodStatus)
			writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"}})
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var claims struct {
			Iss string `json:"iss"`
		}
		if json.Unmarshal(raw, &claims) != nil || claims.Iss != testIssuer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{"id": "task-v03", "status": map[string]interface{}{"state": "completed"}}})
	}))
}

func TestPeerImpersonation_V03AgentIsStillTested(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
	}{
		{name: "RPC 200", status: http.StatusOK},
		{name: "HTTP 400", status: http.StatusBadRequest},
		{name: "HTTP 404", status: http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ts := v03IssuerAllowlistServer(t, tt.status)
			defer ts.Close()

			exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
			findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) == 0 {
				t.Fatal("expected a finding from the v0.3 agent")
			}
			if !strings.Contains(findings[0].Evidence, "v0.3 message/send") {
				t.Errorf("evidence should name the revision that answered, got: %s", findings[0].Evidence)
			}
		})
	}
}

// An agent implementing neither send method tells us nothing about credential
// handling, so it must be not-tested rather than clean.
func TestPeerImpersonation_NoSendMethodIsInconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, cardWithIssuer("no-send"))
			return
		}
		writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": 1,
			"error": map[string]interface{}{"code": -32601, "message": "Method not found"}})
	}))
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive when no send method exists, got err=%v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestPeerImpersonation_ServiceErrorDoesNotProveMethodAbsent(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
	}{
		{name: "timeout", status: http.StatusRequestTimeout},
		{name: "rate limited", status: http.StatusTooManyRequests},
		{name: "unavailable", status: http.StatusServiceUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "agent-card.json") {
					writeJSON(w, cardWithIssuer("peer-agent"))
					return
				}
				req := readBody(r)
				switch req["method"] {
				case "GetTask", "tasks/get":
					rpcErr(w, req["id"], -32001, "Task not found")
				case "SendMessage":
					w.WriteHeader(tt.status)
					rpcErr(w, req["id"], -32601, "Method not found")
				case "message/send":
					w.WriteHeader(http.StatusUnauthorized)
				}
			}))
			defer ts.Close()

			exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
			findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("want incomplete after a v1 service failure, got findings=%v err=%v", findings, err)
			}
			if !strings.Contains(err.Error(), "v1.0 SendMessage forged token response") {
				t.Fatalf("missing v1 service failure reason: %v", err)
			}
		})
	}
}

func TestPeerImpersonation_UnjudgedResponsesAreInconclusive(t *testing.T) {
	tests := []struct {
		name           string
		forgedStatus   int
		baselineStatus int
		forgedError    string
		baselineError  string
	}{
		{name: "both unavailable", forgedStatus: http.StatusServiceUnavailable, baselineStatus: http.StatusServiceUnavailable},
		{name: "forged unavailable", forgedStatus: http.StatusServiceUnavailable, baselineStatus: http.StatusUnauthorized},
		{name: "baseline unavailable", forgedStatus: http.StatusOK, baselineStatus: http.StatusServiceUnavailable},
		{name: "forged application error", forgedStatus: http.StatusOK, baselineStatus: http.StatusUnauthorized, forgedError: "Task not found"},
		{name: "baseline application error", forgedStatus: http.StatusOK, baselineStatus: http.StatusOK, baselineError: "Task not found"},
		{name: "service error with auth text", forgedStatus: http.StatusServiceUnavailable, baselineStatus: http.StatusUnauthorized, forgedError: "unauthorized"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "agent-card.json") {
					writeJSON(w, cardWithIssuer("peer-agent"))
					return
				}
				req := readBody(r)
				if req["method"] == "GetTask" || req["method"] == "tasks/get" {
					rpcErr(w, req["id"], -32001, "Task not found")
					return
				}
				status := tt.baselineStatus
				errorMessage := tt.baselineError
				if r.Header.Get("Authorization") != "" {
					status = tt.forgedStatus
					errorMessage = tt.forgedError
				}
				if status != http.StatusOK {
					w.WriteHeader(status)
				}
				if errorMessage != "" {
					rpcErr(w, req["id"], -32001, errorMessage)
					return
				}
				if status != http.StatusOK {
					return
				}
				writeJSON(w, map[string]interface{}{
					"jsonrpc": "2.0", "id": req["id"],
					"result": map[string]interface{}{"id": "task-001"},
				})
			}))
			defer ts.Close()

			exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
			findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("want incomplete without findings, got findings=%v err=%v", findings, err)
			}
		})
	}
}

func TestPeerImpersonation_MismatchedWireDoesNotProduceCleanResult(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, cardWithIssuer("peer-agent"))
			return
		}
		req := readBody(r)
		switch req["method"] {
		case "GetTask", "tasks/get":
			rpcErr(w, req["id"], -32001, "Task not found")
		case "SendMessage":
			if r.Header.Get("Authorization") != "" {
				rpcErr(w, req["id"], -32601, "Method not found")
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "message/send":
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("want incomplete without findings, got findings=%v err=%v", findings, err)
	}
	if !strings.Contains(err.Error(), "method availability differed") {
		t.Fatalf("missing mismatched wire reason: %v", err)
	}
}

func TestPeerImpersonation_FindingSurvivesMismatchedWire(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, cardWithIssuer("peer-agent"))
			return
		}
		req := readBody(r)
		switch req["method"] {
		case "GetTask", "tasks/get":
			rpcErr(w, req["id"], -32001, "Task not found")
		case "SendMessage":
			if r.Header.Get("Authorization") != "" {
				rpcErr(w, req["id"], -32601, "Method not found")
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "message/send":
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeJSON(w, map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]interface{}{"id": "task-001"},
			})
		}
	}))
	defer ts.Close()

	exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
	findings, err := exec.Execute(context.Background(), ts.URL, testOpts())
	if err != nil || len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("want high finding from v0.3 probe, got findings=%v err=%v", findings, err)
	}
}

// Both the forged token's issuer and the finding's evidence come from a walk over
// the card's securitySchemes map, and Go randomizes map order. A card declaring two
// issuer-bearing schemes is normal during an IdP migration. Measured before the
// fix: two distinct issuers across 30 runs.
func TestPeerImpersonation_IssuerIsDeterministic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "agent-card.json") {
			writeJSON(w, map[string]interface{}{
				"name": "two-idp", "version": "1.0",
				"securitySchemes": map[string]interface{}{
					"legacy-sso": map[string]interface{}{
						"type":             "openIdConnect",
						"openIdConnectUrl": "https://old-idp.example.test/.well-known/openid-configuration",
					},
					"new-sso": map[string]interface{}{
						"type": "oauth2",
						"flows": map[string]interface{}{
							"clientCredentials": map[string]interface{}{
								"tokenUrl": "https://new-idp.example.test/oauth/token",
								"scopes":   map[string]interface{}{},
							},
						},
					},
				},
			})
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": 1,
			"result": map[string]interface{}{"id": "t", "status": map[string]interface{}{"state": "completed"}}})
	}))
	defer srv.Close()

	first := ""
	for i := 0; i < 30; i++ {
		exec := a2aattack.NewPeerImpersonationExecutor(peerImpersonationRC())
		f, err := exec.Execute(context.Background(), srv.URL, testOpts())
		if err != nil || len(f) == 0 {
			t.Fatalf("run %d: expected a finding, got %d findings err=%v", i, len(f), err)
		}
		var iss string
		for _, line := range strings.Split(f[0].Evidence, "\n") {
			if strings.HasPrefix(line, "iss: ") {
				iss = line
			}
		}
		if i == 0 {
			first = iss
			continue
		}
		if iss != first {
			t.Fatalf("run %d derived %q but run 0 derived %q; the issuer must not depend on map order", i, iss, first)
		}
	}
}
