package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

type crossoverPending struct {
	content map[string]string
	reply   chan map[string]string
}

type crossoverFixture struct {
	mode    string
	mu      sync.Mutex
	pending *crossoverPending
}

func (f *crossoverFixture) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage        `json:"id"`
		Method string                 `json:"method"`
		Params map[string]interface{} `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	respond := func(result interface{}, id json.RawMessage) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result})
	}
	meta, _ := req.Params["_meta"].(map[string]interface{})
	if r.Header.Get("MCP-Protocol-Version") != "2026-07-28" ||
		r.Header.Get("Mcp-Method") != req.Method ||
		meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
		http.Error(w, "wrong wire", http.StatusBadRequest)
		return
	}
	principal := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if principal != "owner-token" && principal != "caller-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch req.Method {
	case "server/discover":
		capabilities := map[string]interface{}{"resources": map[string]interface{}{}}
		if f.mode == "no-resources" {
			capabilities = map[string]interface{}{}
		}
		respond(map[string]interface{}{"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
			"capabilities": capabilities}, req.ID)
	case "resources/list":
		uri := "resource://owner/private"
		if principal == "caller-token" {
			uri = "resource://caller/private"
		}
		respond(map[string]interface{}{"resultType": "complete", "resources": []map[string]string{{"uri": uri}}}, req.ID)
	case "resources/read":
		uri, _ := req.Params["uri"].(string)
		if r.Header.Get("Mcp-Name") != uri {
			http.Error(w, "wrong name", http.StatusBadRequest)
			return
		}
		if principal == "caller-token" && uri == "resource://owner/private" && f.mode != "no-denial" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		content := map[string]string{"uri": uri}
		switch uri {
		case "resource://owner/private":
			content["text"] = "owner-secret"
		case "resource://caller/private":
			content["text"] = "caller-content"
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		id, _ := strconv.Atoi(string(req.ID))
		if f.mode == "unstable-post" && id >= 600 && uri == "resource://owner/private" {
			content["text"] = "changed-owner-content"
		}
		if id >= 500 && id < 503 {
			if f.mode == "incomplete-pair" && principal == "caller-token" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if f.mode == "vulnerable" || f.mode == "unstable-post" || f.mode == "wrong-id" {
				ticket := &crossoverPending{content: content, reply: make(chan map[string]string, 1)}
				f.mu.Lock()
				first := f.pending
				if first == nil {
					f.pending = ticket
				}
				f.mu.Unlock()
				if first == nil {
					select {
					case content = <-ticket.reply:
					case <-r.Context().Done():
						return
					}
				} else {
					f.mu.Lock()
					f.pending = nil
					f.mu.Unlock()
					first.reply <- content
					content = first.content
				}
			}
		}
		responseID := req.ID
		if f.mode == "wrong-id" && principal == "caller-token" && id >= 500 && id < 503 {
			responseID = json.RawMessage(strconv.Itoa(id + 1))
		}
		respond(map[string]interface{}{"resultType": "complete", "contents": []map[string]string{content}}, responseID)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func runCrossoverFixture(t *testing.T, mode string) ([]attack.Finding, error) {
	t.Helper()
	fixture := &crossoverFixture{mode: mode}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	opts := testOpts()
	opts.Principals = []attack.Principal{
		{Name: "owner", Token: "owner-token"},
		{Name: "caller", Token: "caller-token"},
	}
	return mcpattack.NewResponseCrossoverExecutor(attack.RuleContext{
		ID: "mcp-response-crossover-001", Name: "MCP response crossover", Remediation: "Isolate responses by request.",
	}).Execute(context.Background(), server.URL, opts)
}

func TestResponseCrossover_Observed(t *testing.T) {
	findings, err := runCrossoverFixture(t, "vulnerable")
	if err != nil || len(findings) != 1 || findings[0].Confidence != attack.ConfirmedExploit {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	encoded, _ := json.Marshal(findings)
	for _, secret := range []string{"owner-secret", "caller-content", "resource://", "owner-token", "caller-token"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("finding disclosed resource or credential: %s", encoded)
		}
	}
}

func TestResponseCrossover_ProtectedAndIncomplete(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		incomplete bool
	}{
		{"protected", false},
		{"no-resources", true},
		{"no-denial", true},
		{"incomplete-pair", true},
		{"wrong-id", true},
		{"unstable-post", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			findings, err := runCrossoverFixture(t, tc.mode)
			if len(findings) != 0 || errors.Is(err, attack.ErrInconclusive) != tc.incomplete {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestResponseCrossover_RequiresDistinctPrincipals(t *testing.T) {
	exec := mcpattack.NewResponseCrossoverExecutor(attack.RuleContext{ID: "mcp-response-crossover-001"})
	for _, principals := range [][]attack.Principal{
		nil,
		{{Name: "a", Token: "same"}, {Name: "b", Token: "same"}},
	} {
		findings, err := exec.Execute(t.Context(), "http://127.0.0.1:1", attack.Options{Principals: principals})
		if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("principals=%+v findings=%+v err=%v", principals, findings, err)
		}
	}
}
