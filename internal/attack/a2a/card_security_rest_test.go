package a2a_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func cardSecurityRESTServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "message-v03" && r.URL.Path == "/.well-known/agent.json" {
			writeJSON(w, map[string]interface{}{
				"name": "Legacy REST security fixture", "url": "http://" + r.Host + "/rest",
				"preferredTransport": "HTTP+JSON",
				"securitySchemes": map[string]interface{}{"bearerAuth": map[string]interface{}{
					"httpAuthSecurityScheme": map[string]string{"scheme": "Bearer"}}},
				"security": []interface{}{map[string]interface{}{"bearerAuth": []string{}}},
				"additionalInterfaces": []interface{}{map[string]string{
					"url": "http://" + r.Host + "/rest", "transport": "HTTP+JSON", "protocolVersion": "0.3.0"}},
			})
			return
		}
		if r.URL.Path == "/.well-known/agent-card.json" {
			if mode == "message-v03" {
				http.NotFound(w, r)
				return
			}
			interfaces := []interface{}{map[string]string{
				"url": "http://" + r.Host + "/rest", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}}
			if mode == "rpc-down" {
				interfaces = append(interfaces, map[string]string{
					"url": "http://" + r.Host + "/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"})
			}
			writeJSON(w, map[string]interface{}{
				"name": "REST security fixture", "description": "test", "version": "1.0.0",
				"capabilities": map[string]interface{}{}, "skills": []interface{}{},
				"defaultInputModes": []string{"text/plain"}, "defaultOutputModes": []string{"text/plain"},
				"securitySchemes": map[string]interface{}{"bearerAuth": map[string]interface{}{
					"httpAuthSecurityScheme": map[string]string{"scheme": "Bearer"}}},
				"securityRequirements": []interface{}{map[string]interface{}{
					"schemes": map[string]interface{}{"bearerAuth": map[string]interface{}{"list": []string{"a2a:invoke"}}}}},
				"supportedInterfaces": interfaces,
			})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/rest/") {
			http.NotFound(w, r)
			return
		}
		if mode == "secure" || mode == "rpc-down" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/rest/message:send":
			if mode == "message-v03" {
				http.NotFound(w, r)
				return
			}
			if mode == "malformed" {
				writeJSON(w, map[string]bool{"ok": true})
				return
			}
			var request map[string]interface{}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request["message"] == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if mode == "message-echo" {
				message, _ := request["message"].(map[string]interface{})
				message["role"] = "ROLE_AGENT"
				message["contextId"] = "rest-context-1"
				writeJSON(w, map[string]interface{}{"message": message})
				return
			}
			if mode == "message" || mode == "message-malformed" {
				parts := []interface{}{map[string]string{"text": "pong"}}
				if mode == "message-malformed" {
					parts = nil
				}
				writeJSON(w, map[string]interface{}{"message": map[string]interface{}{
					"messageId": "rest-reply-1", "contextId": "rest-context-1",
					"role": "ROLE_AGENT", "parts": parts,
				}})
				return
			}
			writeJSON(w, map[string]interface{}{"task": map[string]interface{}{
				"id": "rest-task-1", "contextId": "rest-context-1",
				"status": map[string]string{"state": "TASK_STATE_SUBMITTED"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/rest/v1/message:send" && mode == "message-v03":
			writeJSON(w, map[string]interface{}{"message": map[string]interface{}{
				"messageId": "rest-v03-reply", "role": "ROLE_AGENT",
				"content": []interface{}{map[string]string{"text": "pong"}},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/rest/tasks/rest-task-1":
			writeJSON(w, map[string]interface{}{
				"id": "rest-task-1", "contextId": "rest-context-1",
				"status": map[string]string{"state": "TASK_STATE_SUBMITTED"}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestCardSecurityRESTOnly(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		wantFinding bool
		wantErr     bool
	}{
		{"vulnerable", true, false},
		{"secure", false, false},
		{"rpc-down", false, true},
		{"malformed", false, true},
		{"message", true, false},
		{"message-v03", true, false},
		{"message-echo", false, true},
		{"message-malformed", false, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			srv := cardSecurityRESTServer(tc.mode)
			defer srv.Close()
			findings, err := runCardSec(t, srv)
			if (len(findings) == 1) != tc.wantFinding {
				t.Fatalf("findings = %+v, want finding %t", findings, tc.wantFinding)
			}
			if tc.wantErr != errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("error = %v, want inconclusive %t", err, tc.wantErr)
			}
			if tc.wantFinding {
				route := "POST /message:send"
				if tc.mode == "message-v03" {
					route = "POST /v1/message:send"
				}
				if !strings.Contains(findings[0].Evidence, route) {
					t.Fatalf("REST binding missing from evidence: %s", findings[0].Evidence)
				}
			}
			if tc.mode == "message" && !strings.Contains(findings[0].Evidence, "agent Message rest-reply-1") {
				t.Fatalf("REST Message missing from evidence: %s", findings[0].Evidence)
			}
			if tc.mode == "message-v03" && !strings.Contains(findings[0].Evidence, "agent Message rest-v03-reply") {
				t.Fatalf("legacy REST Message missing from evidence: %s", findings[0].Evidence)
			}
		})
	}
}
