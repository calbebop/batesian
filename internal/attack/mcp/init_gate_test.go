package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func gateErrorServer(t *testing.T, phase string, status, code int, message string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if (phase == "initialize" && req.Method == "initialize") ||
			(phase == "method" && req.Method == "tools/list") ||
			(phase == "forged-initialize" && req.Method == "initialize" && r.Header.Get("Authorization") != "") {
			w.WriteHeader(status)
			if status != http.StatusUnauthorized {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"error": map[string]interface{}{"code": code, "message": message},
				})
			}
			return
		}
		result := map[string]interface{}{"tools": []interface{}{}}
		if req.Method == "initialize" {
			result = map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"serverInfo":      map[string]interface{}{"name": "gate-test", "version": "1"},
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
}

func TestProbeInitGate_RequiresAuthRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, phase, message string
		status, code         int
		want                 initGate
	}{
		{"resource miss at initialize", "initialize", "Resource not found", 200, -32002, gateUnknown},
		{"session miss at initialize", "initialize", "Session not found", 200, -32001, gateUnknown},
		{"resource miss at method", "method", "Resource not found", 200, -32002, gateUnknown},
		{"session miss at method", "method", "Session not found", 200, -32001, gateUnknown},
		{"auth message at initialize", "initialize", "Permission denied", 200, -32002, gateOnInit},
		{"auth status at initialize", "initialize", "", 401, 0, gateOnInit},
		{"auth message at method", "method", "Permission denied", 200, -32002, gateAfterInit},
		{"auth status at method", "method", "", 401, 0, gateAfterInit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := gateErrorServer(t, tc.phase, tc.status, tc.code, tc.message)
			defer srv.Close()
			client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(srv.URL, ""))
			got := probeInitGate(context.Background(), client, srv.URL)
			if got.gate != tc.want {
				t.Fatalf("gate = %v, want %v; reason: %s", got.gate, tc.want, got.reason)
			}
		})
	}
}

func TestProbeForgedAtMethod_RequiresAuthRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, phase, message string
		code                 int
		want                 accessVerdict
	}{
		{"resource miss at method", "method", "Resource not found", -32002, accessUndetermined},
		{"session miss at method", "method", "Session not found", -32001, accessUndetermined},
		{"session miss at initialize", "forged-initialize", "Session not found", -32001, accessUndetermined},
		{"auth message at initialize", "forged-initialize", "Permission denied", -32002, accessRefused},
		{"auth message at method", "method", "Permission denied", -32002, accessRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := gateErrorServer(t, tc.phase, 200, tc.code, tc.message)
			defer srv.Close()
			client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(srv.URL, ""))
			_, got, _ := probeForgedAtMethod(context.Background(), client, srv.URL, "tools/list", "forged")
			if got != tc.want {
				t.Fatalf("verdict = %v, want %v", got, tc.want)
			}
		})
	}
}
