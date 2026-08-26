package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func originPfxRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-origin-prefix-bypass-001",
		Name:        "MCP Origin Prefix Bypass",
		Severity:    "high",
		Remediation: "Parse the Origin and compare scheme and host individually.",
	}
}

// originPfxServer validates the Origin header with a chosen strategy:
//
//	prefix       strings.HasPrefix(origin, ownOrigin)        (vulnerable)
//	none         no validation at all                        (suppressed)
//	parsed-host  scheme+host equality after url.Parse        (patched)
type originPfxStrategy string

const (
	opfxPrefix     originPfxStrategy = "prefix"
	opfxNone       originPfxStrategy = "none"
	opfxParsedHost originPfxStrategy = "parsed-host"
)

func originPfxHandler(strategy originPfxStrategy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch req.Method {
		case "initialize":
			if !originAllowed(strategy, r.Header.Get("Origin"), "http://"+r.Host) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "originpfx-fixture", "version": "1"},
				},
			})
			return
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32601, "message": "Method not found"},
			})
		}
	}
}

// originAllowed implements each strategy against the server's own origin.
func originAllowed(strategy originPfxStrategy, origin, own string) bool {
	switch strategy {
	case opfxPrefix:
		// The published bug shape: literal prefix, no parse. An empty Origin
		// (non-browser clients send none) passes; this is what makes the
		// baseline handshake succeed for the scanner too.
		if origin == "" {
			return true
		}
		return strings.HasPrefix(origin, own)
	case opfxNone:
		return true
	case opfxParsedHost:
		if origin == "" {
			return true
		}
		uo, err1 := url.Parse(origin)
		uo2, err2 := url.Parse(own)
		if err1 != nil || err2 != nil {
			return false
		}
		// A crafted attacker subdomain shares the string but not the host.
		return strings.EqualFold(uo.Scheme, uo2.Scheme) &&
			strings.EqualFold(uo.Host, uo2.Host)
	}
	return false
}

func runOriginPfx(t *testing.T, ts *httptest.Server) ([]attack.Finding, error) {
	t.Helper()
	return mcp.NewOriginPrefixBypassExecutor(originPfxRC()).
		Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
}

// TestOriginPfx_PrefixMatchFires: control rejected, attacker-subdomain origin
// accepted. MUST fire confirmed/high naming the craft in evidence.
func TestOriginPfx_PrefixMatchFires(t *testing.T) {
	ts := httptest.NewServer(originPfxHandler(opfxPrefix))
	defer ts.Close()

	findings, err := runOriginPfx(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "high" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want high/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "control") || !strings.Contains(f.Evidence, "ACCEPTED") {
		t.Errorf("evidence should show the control-rejected / probe-accepted pair, got: %q", f.Evidence)
	}
}

// TestOriginPfx_OpenSuppressed: no validation anywhere. The control twin is
// accepted too, so there is no validator to bypass and the surface belongs to
// mcp-dns-rebind-origin-001.
func TestOriginPfx_OpenSuppressed(t *testing.T) {
	ts := httptest.NewServer(originPfxHandler(opfxNone))
	defer ts.Close()

	findings, err := runOriginPfx(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings when nothing validates Origin, got %d: %+v", len(findings), findings)
	}
}

// TestOriginPfx_ParsedHostClean: correct scheme+host comparison rejects every
// craft while still admitting empty-Origin baselines. MUST stay silent.
func TestOriginPfx_ParsedHostClean(t *testing.T) {
	ts := httptest.NewServer(originPfxHandler(opfxParsedHost))
	defer ts.Close()

	findings, err := runOriginPfx(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings under parsed-host validation, got %d: %+v", len(findings), findings)
	}
}

// TestOriginPfx_UserinfoCraftFires: a hardened validator that special-cases
// plain foreign origins but compares with Contains still accepts the userinfo
// smuggle. Both crafts must be attempted before concluding clean.
func TestOriginPfx_UserinfoCraftFires(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req struct {
			Method string      `json:"method"`
			ID     json.Number `json:"id"`
		}
		if json.Unmarshal(raw, &req) != nil || req.Method == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Method != "initialize" {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		origin := r.Header.Get("Origin")
		host := "127.0.0.1:" + portOfServer(r.Host)
		switch {
		case origin == "":
			// baseline
		case !strings.Contains(origin, "prefix-rebind"):
			// Fully foreign: rejected (a validator exists here).
			w.WriteHeader(http.StatusForbidden)
			return
		case strings.Contains(origin, "prefix-rebind") && !strings.Contains(origin, "@"):
			// The subdomain craft was special-cased away by an upstream fix...
			w.WriteHeader(http.StatusForbidden)
			return
		default:
			if !strings.Contains(origin, host) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]interface{}{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "originpfx-userinfo", "version": "1"},
			},
		})
	}))
	defer ts.Close()

	findings, err := runOriginPfx(t, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding via the userinfo craft, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Evidence, "@") {
		t.Errorf("expected evidence to name the userinfo smuggle origin, got: %q", findings[0].Evidence)
	}
}

func portOfServer(hostPort string) string {
	if i := strings.LastIndex(hostPort, ":"); i >= 0 {
		return hostPort[i+1:]
	}
	return hostPort
}
