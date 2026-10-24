package a2a_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

func tenantRESTServer(version, mode string) *httptest.Server {
	var server *httptest.Server
	var mu sync.Mutex
	markers := map[string]string{}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"supportedInterfaces": []any{
				map[string]string{"url": server.URL + "/agent", "protocolBinding": "HTTP+JSON", "protocolVersion": version},
			}})
			return
		}
		prefix := "/agent"
		if version != "1.0" {
			prefix += "/v1"
		}
		if !strings.HasPrefix(r.URL.Path, prefix+"/") || mode == "no-routes" {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, prefix)
		who := tenantOf(r)
		writeTask := func(id, marker string) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": id, "contextId": "ctx-" + strings.TrimPrefix(id, "task-"),
				"status":  map[string]string{"state": "TASK_STATE_WORKING"},
				"history": []any{map[string]any{"parts": []any{map[string]string{"text": marker}}}},
			})
		}
		switch {
		case r.Method == http.MethodPost && path == "/message:send":
			if who == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var body struct {
				Message struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"message"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			marker := ""
			if len(body.Message.Parts) != 0 {
				marker = body.Message.Parts[0].Text
			} else if len(body.Message.Content) != 0 {
				marker = body.Message.Content[0].Text
			}
			if marker == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			id := "task-" + who
			if mode == "shared-id" {
				id = "task-shared"
			}
			mu.Lock()
			markers[id] = marker
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"task": map[string]any{
				"id": id, "contextId": "ctx-" + who,
				"status": map[string]string{"state": "TASK_STATE_WORKING"},
			}})
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/tasks/"):
			if r.URL.Query().Get("historyLength") != "10" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			id := strings.TrimPrefix(path, "/tasks/")
			mu.Lock()
			marker, exists := markers[id]
			mu.Unlock()
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			owner := strings.TrimPrefix(id, "task-")
			if who == "" && mode != "public-read" || who != "" && who != owner && mode == "secure" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if mode == "owner-redacted" && who == "A" && owner == "A" {
				marker = "redacted"
			}
			if mode == "cross-wrong-id" && who == "B" && owner == "A" {
				id = "task-other"
			}
			writeTask(id, marker)
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

func TestMultiTenantREST(t *testing.T) {
	for _, tc := range []struct {
		version, mode string
		findings      int
		inconclusive  bool
	}{
		{"1.0", "secure", 0, false},
		{"1.0", "vulnerable", 2, false},
		{"1.0", "public-read", 0, false},
		{"1.0", "owner-redacted", 1, true},
		{"1.0", "cross-wrong-id", 1, true},
		{"1.0", "shared-id", 0, true},
		{"1.0", "no-routes", 0, true},
		{"0.3.0", "secure", 0, false},
		{"0.3.0", "vulnerable", 2, false},
	} {
		t.Run(tc.version+"-"+tc.mode, func(t *testing.T) {
			server := tenantRESTServer(tc.version, tc.mode)
			defer server.Close()
			findings, err := a2a.NewMultiTenantIsolationExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
				attack.Options{TimeoutSeconds: 3, Principals: tenantPrincipals()})
			if len(findings) != tc.findings || errors.Is(err, attack.ErrInconclusive) != tc.inconclusive ||
				err != nil && !tc.inconclusive {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			for _, finding := range findings {
				if finding.Confidence != attack.ConfirmedExploit ||
					!strings.Contains(finding.Evidence, "method: GET ") ||
					!strings.Contains(finding.TargetURL, "/agent/") {
					t.Fatalf("finding=%+v", finding)
				}
			}
		})
	}
}

func TestMultiTenantRESTHeaderScopedPrincipals(t *testing.T) {
	server := tenantRESTServer("1.0", "vulnerable")
	defer server.Close()
	principals := []attack.Principal{
		{Name: "tenant-a", Tenant: "A", Headers: map[string]string{"X-API-Key": "key-a"}},
		{Name: "tenant-b", Tenant: "B", Headers: map[string]string{"X-API-Key": "key-b"}},
	}
	findings, err := a2a.NewMultiTenantIsolationExecutor(testRuleCtx()).Execute(t.Context(), server.URL,
		attack.Options{TimeoutSeconds: 3, Principals: principals})
	if err != nil || len(findings) != 2 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
}
