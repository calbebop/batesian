package a2a_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack/a2a"
)

func v03ExtendedCard(url, transport string) map[string]interface{} {
	return map[string]interface{}{
		"name": "Legacy Agent", "description": "Private capabilities", "version": "1.0.0",
		"url": url, "protocolVersion": "0.3.0", "preferredTransport": transport,
		"supportsAuthenticatedExtendedCard": true,
		"capabilities":                      map[string]interface{}{},
		"defaultInputModes":                 []string{"text/plain"},
		"defaultOutputModes":                []string{"text/plain"},
		"skills": []map[string]interface{}{{
			"id": "private", "name": "Private", "description": "Private skill", "tags": []string{"private"},
		}},
	}
}

func TestExtCard_V03JSONRPC(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		want string
	}{
		{"invalid token accepted", "invalid", "critical"},
		{"anonymous only", "anonymous", "high"},
		{"protected", "protected", ""},
		{"partial response", "partial", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var origin string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/agent.json":
					writeJSON(w, v03ExtendedCard(origin+"/rpc", "JSONRPC"))
				case "/rpc":
					request := readBody(r)
					if request["method"] != "agent/getAuthenticatedExtendedCard" {
						rpcErr(w, request["id"], -32601, "method not found")
						return
					}
					if r.Header.Get("A2A-Version") != "" {
						http.Error(w, "unexpected version header", http.StatusBadRequest)
						return
					}
					auth := r.Header.Get("Authorization")
					if tc.mode == "protected" || tc.mode == "anonymous" && auth != "" ||
						tc.mode == "invalid" && !strings.HasPrefix(auth, "Bearer batesian-invalid-") {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					card := interface{}(v03ExtendedCard(origin+"/rpc", "JSONRPC"))
					if tc.mode == "partial" {
						card = map[string]string{"name": "Partial"}
					}
					writeJSON(w, map[string]interface{}{"jsonrpc": "2.0", "id": request["id"], "result": card})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			origin = server.URL
			findings, err := a2a.NewExtCardExecutor(testRuleCtx()).Execute(t.Context(), server.URL, testOpts())
			if err != nil || len(findings) != boolCount(tc.want != "") {
				t.Fatalf("v0.3 JSON-RPC findings=%+v err=%v", findings, err)
			}
			if tc.want != "" && findings[0].Severity != tc.want {
				t.Fatalf("severity=%q, want %q", findings[0].Severity, tc.want)
			}
		})
	}
}

func TestExtCard_V03REST(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		want string
	}{
		{"invalid token accepted", "invalid", "critical"},
		{"anonymous only", "anonymous", "high"},
		{"protected", "protected", ""},
		{"partial response", "partial", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var origin string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/agent.json":
					writeJSON(w, v03ExtendedCard(origin+"/api", "HTTP+JSON"))
				case "/api/v1/card":
					if r.Method != http.MethodGet || r.Header.Get("A2A-Version") != "" {
						http.Error(w, "invalid v0.3 card request", http.StatusBadRequest)
						return
					}
					auth := r.Header.Get("Authorization")
					if tc.mode == "protected" || tc.mode == "anonymous" && auth != "" ||
						tc.mode == "invalid" && !strings.HasPrefix(auth, "Bearer batesian-invalid-") {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if tc.mode == "partial" {
						writeJSON(w, map[string]string{"name": "Partial"})
						return
					}
					writeJSON(w, v03ExtendedCard(origin+"/api", "HTTP+JSON"))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			origin = server.URL
			findings, err := a2a.NewExtCardExecutor(testRuleCtx()).Execute(t.Context(), server.URL, testOpts())
			if err != nil || len(findings) != boolCount(tc.want != "") {
				t.Fatalf("v0.3 REST findings=%+v err=%v", findings, err)
			}
			if tc.want != "" && findings[0].Severity != tc.want {
				t.Fatalf("severity=%q, want %q", findings[0].Severity, tc.want)
			}
		})
	}
}

func TestExtCard_PrefersInvalidTokenAcrossRESTBindings(t *testing.T) {
	var origin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent.json":
			writeJSON(w, v03ExtendedCard(origin, "HTTP+JSON"))
		case "/extendedAgentCard":
			if r.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeJSON(w, extendedCard())
		case "/v1/card":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer batesian-invalid-") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeJSON(w, v03ExtendedCard(origin, "HTTP+JSON"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	origin = server.URL
	findings, err := a2a.NewExtCardExecutor(testRuleCtx()).Execute(t.Context(), server.URL, testOpts())
	if err != nil || len(findings) != 1 || findings[0].Severity != "critical" {
		t.Fatalf("want one invalid-token finding: findings=%+v err=%v", findings, err)
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}
