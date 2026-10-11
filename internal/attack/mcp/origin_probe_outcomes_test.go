package mcp_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func originOutcomeServer(mode string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if req.Method != "initialize" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		origin := r.Header.Get("Origin")
		responseMode := "accepted"
		switch {
		case origin == "":
		case strings.Contains(origin, "dns-rebind.batesian.invalid"):
			if strings.HasPrefix(mode, "control-") {
				responseMode = strings.TrimPrefix(mode, "control-")
			} else {
				responseMode = "rejected"
			}
		case strings.Contains(origin, "prefix-rebind.batesian-invalid.invalid"):
			responseMode = strings.TrimPrefix(mode, "prefix-")
		}
		w.Header().Set("Content-Type", "application/json")
		switch responseMode {
		case "rejected":
			w.WriteHeader(http.StatusForbidden)
			return
		case "gateway":
			w.WriteHeader(http.StatusBadGateway)
			return
		case "unauthorized":
			w.WriteHeader(http.StatusUnauthorized)
			return
		case "rate-limit":
			w.WriteHeader(http.StatusTooManyRequests)
			return
		case "rpc-error":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
			return
		case "stale":
			req.ID = json.RawMessage("99")
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]interface{}{
				"protocolVersion": "2025-11-25",
				"serverInfo":      map[string]interface{}{"name": "origin-outcome", "version": "1"},
				"capabilities":    map[string]interface{}{},
			},
		})
	}))
}

func TestOriginRules_UnansweredControlIsIncomplete(t *testing.T) {
	for _, mode := range []string{"control-gateway", "control-unauthorized", "control-rate-limit", "control-rpc-error", "control-stale"} {
		t.Run(mode, func(t *testing.T) {
			ts := originOutcomeServer(mode)
			defer ts.Close()

			for _, run := range []func(*testing.T, *httptest.Server) ([]attack.Finding, error){runOriginRule, runOriginPfx} {
				findings, err := run(t, ts)
				if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
					t.Fatalf("unanswered control: findings=%+v err=%v", findings, err)
				}
			}
		})
	}
}

func TestOriginPrefix_UnansweredCraftIsIncomplete(t *testing.T) {
	for _, mode := range []string{"prefix-gateway", "prefix-unauthorized", "prefix-rate-limit", "prefix-rpc-error", "prefix-stale"} {
		t.Run(mode, func(t *testing.T) {
			ts := originOutcomeServer(mode)
			defer ts.Close()

			findings, err := runOriginPfx(t, ts)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("unanswered prefix craft: findings=%+v err=%v", findings, err)
			}
			findings, err = runOriginRule(t, ts)
			if len(findings) != 0 || err != nil {
				t.Fatalf("explicit control rejection should still pass the DNS rule: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestOriginRules_ModernProbeOutcomes(t *testing.T) {
	for _, mode := range []string{"control-gateway", "prefix-stale"} {
		t.Run(mode, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Method string      `json:"method"`
					ID     interface{} `json:"id"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				if req.Method != "server/discover" {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": req.ID,
						"error": map[string]interface{}{"code": -32022, "message": "UnsupportedProtocolVersion"},
					})
					return
				}
				origin := r.Header.Get("Origin")
				if mode == "control-gateway" && strings.Contains(origin, "dns-rebind.batesian.invalid") {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				if mode == "prefix-stale" && strings.Contains(origin, "dns-rebind.batesian.invalid") {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if mode == "prefix-stale" && strings.Contains(origin, "prefix-rebind.batesian-invalid.invalid") {
					req.ID = "stale"
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req.ID,
					"result": map[string]interface{}{"supportedVersions": []string{"2026-07-28"}},
				})
			}))
			defer ts.Close()

			findings, err := runOriginPfx(t, ts)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("unanswered modern prefix check: findings=%+v err=%v", findings, err)
			}
			findings, err = runOriginRule(t, ts)
			if mode == "control-gateway" {
				if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
					t.Fatalf("unanswered modern DNS check: findings=%+v err=%v", findings, err)
				}
			} else if len(findings) != 0 || err != nil {
				t.Fatalf("modern 403 should be clean: findings=%+v err=%v", findings, err)
			}
		})
	}
}
