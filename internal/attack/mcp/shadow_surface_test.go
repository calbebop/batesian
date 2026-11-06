package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

func shadowRC() attack.RuleContext {
	return attack.RuleContext{
		ID:          "mcp-shadow-surface-001",
		Name:        "Shadow MCP Surface",
		Severity:    "high",
		Remediation: "Bind inspector processes to loopback behind authentication.",
	}
}

// withShadowPorts points the executor at the given ports for one test,
// restoring the documented list afterwards.
func withShadowPorts(t *testing.T, ports ...int) {
	t.Helper()
	old := mcp.ShadowPorts()
	mcp.SetShadowPorts(ports)
	t.Cleanup(func() { mcp.SetShadowPorts(old) })
}

// shadowMCPHandler models an inspector-style listener: an HTML page naming
// the product, and an MCP initialize that answers on any POST path. The
// foreignOriginRefused flag makes the Origin twin fail, as a hardened
// deployment would.
func shadowMCPHandler(foreignOriginRefused bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><title>MCP Inspector</title><body>proxy ready</body></html>"))
		case foreignOriginRefused && r.Header.Get("Origin") != "":
			http.Error(w, "forbidden origin", http.StatusForbidden)
		case r.Method == http.MethodPost:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			switch req["method"] {
			case "notifications/initialized":
				w.WriteHeader(http.StatusAccepted)
				return
			case "tools/list":
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": req["id"],
					"result": map[string]interface{}{"tools": []interface{}{map[string]string{"name": "inspect"}}},
				})
				return
			case "initialize":
			default:
				http.Error(w, "unknown method", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]interface{}{
					"protocolVersion": "2025-06-18",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "inspector-proxy", "version": "1"},
				},
			})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func runShadow(t *testing.T, target string) ([]attack.Finding, error) {
	t.Helper()
	return mcp.NewShadowSurfaceExecutor(shadowRC()).Execute(context.Background(), target, attack.Options{TimeoutSeconds: 5})
}

// TestShadow_OpenWithOpenOriginFires: an unauthenticated MCP surface on an
// adjacent port that also accepts a foreign-Origin handshake is the full
// browser-reachable chain. MUST fire confirmed/high.
func TestShadow_OpenWithOpenOriginFires(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(shadowMCPHandler(false))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
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
}

// TestShadow_HardenedOriginMedium: the surface is open but refuses the
// foreign-Origin twin. Rebinding is mitigated; the unauthenticated surface
// remains and reports medium.
func TestShadow_HardenedOriginMedium(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(shadowMCPHandler(true))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "medium" || f.Confidence != attack.ConfirmedExploit {
		t.Errorf("want medium/ConfirmedExploit, got %q/%q", f.Severity, f.Confidence)
	}
}

func shadowModernHandler(refuseOrigin, protectList bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req map[string]interface{}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req["method"] == "initialize" {
			http.Error(w, "modern only", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Mcp-Protocol-Version") != "2026-07-28" {
			http.Error(w, "missing modern version", http.StatusBadRequest)
			return
		}
		if refuseOrigin && r.Header.Get("Origin") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req["method"] {
		case "server/discover":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"], "result": map[string]interface{}{
					"resultType": "complete", "supportedVersions": []string{"2026-07-28"},
					"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":   map[string]string{"name": "modern-shadow", "version": "1"},
				},
			})
		case "tools/list":
			if protectList {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req["id"], "result": map[string]interface{}{
					"resultType": "complete", "ttlMs": 0, "cacheScope": "public",
					"tools": []interface{}{map[string]string{"name": "inspect"}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}
}

func TestShadow_ModernOnlySurface(t *testing.T) {
	for _, tc := range []struct {
		name         string
		refuseOrigin bool
		protectList  bool
		severity     string
	}{
		{"open origin", false, false, "high"},
		{"refused origin", true, false, "medium"},
		{"protected list", false, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shadow := httptest.NewServer(shadowModernHandler(tc.refuseOrigin, tc.protectList))
			defer shadow.Close()
			withShadowPorts(t, portOf(shadow.URL))
			findings, err := runShadow(t, "http://127.0.0.1:1")
			wantFindings := 0
			if tc.severity != "" {
				wantFindings = 1
			}
			if err != nil || len(findings) != wantFindings {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			if tc.severity != "" && (findings[0].Severity != tc.severity ||
				!strings.Contains(findings[0].Evidence, "tools/list")) {
				t.Fatalf("modern finding=%+v", findings[0])
			}
		})
	}
}

func TestShadow_ModernRepliesNeedMatchingDiscoveryAndCompleteListing(t *testing.T) {
	for _, tc := range []struct {
		name        string
		wrongID     bool
		partialList bool
	}{
		{"unmatched discovery", true, false},
		{"incomplete listing", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					var req map[string]interface{}
					_ = json.NewDecoder(r.Body).Decode(&req)
					if req["method"] == "server/discover" && tc.wrongID {
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"jsonrpc": "2.0", "id": "unrelated",
							"result": map[string]interface{}{"supportedVersions": []string{"2026-07-28"},
								"capabilities": map[string]interface{}{"tools": map[string]interface{}{}}},
						})
						return
					}
					if req["method"] == "tools/list" && tc.partialList {
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"jsonrpc": "2.0", "id": req["id"],
							"result": map[string]interface{}{"resultType": "input_required",
								"tools": []interface{}{map[string]string{"name": "inspect"}}},
						})
						return
					}
					body, _ := json.Marshal(req)
					r.Body = io.NopCloser(bytes.NewReader(body))
				}
				shadowModernHandler(false, false)(w, r)
			}))
			defer shadow.Close()
			withShadowPorts(t, portOf(shadow.URL))
			findings, err := runShadow(t, "http://127.0.0.1:1")
			if len(findings) != 0 || (tc.partialList && !errors.Is(err, attack.ErrInconclusive)) ||
				(!tc.partialList && err != nil) {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestShadow_ClosesLegacySessions(t *testing.T) {
	for _, protectList := range []bool{false, true} {
		t.Run(strconv.FormatBool(protectList), func(t *testing.T) {
			var mu sync.Mutex
			var closed []string
			shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					mu.Lock()
					closed = append(closed, r.Header.Get("Mcp-Session-Id")+":"+r.Header.Get("Origin"))
					mu.Unlock()
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.Method != http.MethodPost {
					http.NotFound(w, r)
					return
				}
				var req map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				switch req["method"] {
				case "initialize":
					id := "baseline"
					if r.Header.Get("Origin") != "" {
						id = "foreign"
					}
					w.Header().Set("Mcp-Session-Id", id)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": req["id"], "result": map[string]interface{}{
							"protocolVersion": "2025-11-25",
							"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
							"serverInfo":      map[string]string{"name": "legacy-shadow", "version": "1"},
						},
					})
				case "tools/list":
					if protectList {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"jsonrpc": "2.0", "id": req["id"],
						"result": map[string]interface{}{"tools": []interface{}{map[string]string{"name": "inspect"}}},
					})
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				default:
					http.NotFound(w, r)
				}
			}))
			defer shadow.Close()
			withShadowPorts(t, portOf(shadow.URL))
			_, err := runShadow(t, "http://127.0.0.1:1")
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			want := []string{"baseline:"}
			if !protectList {
				want = append(want, "foreign:https://dns-rebind.batesian.invalid")
			}
			slices.Sort(closed)
			slices.Sort(want)
			if !slices.Equal(closed, want) {
				t.Fatalf("closed=%v want=%v", closed, want)
			}
		})
	}
}

func TestShadow_IPv6AdjacentPort(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	shadow := httptest.NewUnstartedServer(shadowModernHandler(false, false))
	shadow.Listener = listener
	shadow.Start()
	defer shadow.Close()
	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, "http://[::1]:1")
	if err != nil || len(findings) != 1 || findings[0].Severity != "high" {
		t.Fatalf("IPv6 findings=%+v err=%v", findings, err)
	}
}

func TestShadow_ProtectedOperationsAreNotConfirmed(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["method"] == "tools/list" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			r.Body.Close()
			body, _ := json.Marshal(req)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		shadowMCPHandler(true)(w, r)
	}))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil || len(findings) != 1 || findings[0].Severity != "low" || findings[0].Confidence != attack.RiskIndicator {
		t.Fatalf("protected operations must not be confirmed: findings=%+v err=%v", findings, err)
	}
}

func TestShadow_ProtectedOperationsWithoutDashboardAreClean(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.NotFound(w, r)
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["method"] == "tools/list" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := json.Marshal(req)
		r.Body = io.NopCloser(bytes.NewReader(body))
		shadowMCPHandler(true)(w, r)
	}))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil || len(findings) != 0 {
		t.Fatalf("protected operations were reported: findings=%+v err=%v", findings, err)
	}
}

func TestShadow_ForeignOriginMustReachListingForHigh(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&req)
			if r.Header.Get("Origin") != "" && req["method"] == "tools/list" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			body, _ := json.Marshal(req)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		shadowMCPHandler(false)(w, r)
	}))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil || len(findings) != 1 || findings[0].Severity != "medium" ||
		!strings.Contains(findings[0].Evidence, "refused (HTTP 403)") {
		t.Fatalf("foreign listing refusal was overstated: findings=%+v err=%v", findings, err)
	}
}

func TestShadow_MalformedInitializeDoesNotConfirm(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"protocolVersion":"x"}}`))
	}))
	defer shadow.Close()
	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil || len(findings) != 0 {
		t.Fatalf("malformed initialize was accepted: findings=%+v err=%v", findings, err)
	}
}

func TestShadow_UnobservedOriginDoesNotClaimRefusal(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		shadowMCPHandler(false)(w, r)
	}))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if findings[0].Severity != "medium" ||
		!strings.Contains(findings[0].Evidence, "inconclusive (HTTP 429)") ||
		strings.Contains(findings[0].Evidence, "refused") ||
		!strings.Contains(findings[0].Description, "was not assessed") {
		t.Fatalf("unobserved Origin result was misreported: %+v", findings[0])
	}
}

// TestShadow_FingerprintOnlyLow: the page names a known product but no MCP
// endpoint answers. Low indicator, not silence - the dashboard is exposed
// even though its protocol could not be driven from here.
func TestShadow_FingerprintOnlyLow(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dashboard page on every path, protocol never answers: exactly the
		// "exposed product page, undriven control plane" posture.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><title>Serena Dashboard</title></html>"))
	}))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != "low" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("want low/RiskIndicator, got %q/%q", findings[0].Severity, findings[0].Confidence)
	}
}

func TestShadow_FingerprintWithIncompleteHandshake(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("<html><title>Serena Dashboard</title></html>"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	findings, err := runShadow(t, main.URL)
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 1 || findings[0].Severity != "low" ||
		!strings.Contains(findings[0].Evidence, "handshake probes incomplete") {
		t.Fatalf("dashboard finding must retain incomplete handshake evidence: findings=%+v err=%v", findings, err)
	}
}

func TestShadow_OpenSurfaceKeepsIncompletePeerProbe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "dashboard read", handler: func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			shadowMCPHandler(false)(w, r)
		}},
		{name: "alternate MCP path", handler: func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/mcp" {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			shadowMCPHandler(false)(w, r)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			main := httptest.NewServer(http.NotFoundHandler())
			defer main.Close()
			shadow := httptest.NewServer(tc.handler)
			defer shadow.Close()

			withShadowPorts(t, portOf(shadow.URL))
			findings, err := runShadow(t, main.URL)
			if len(findings) != 1 || findings[0].Severity != "high" ||
				!errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("want open-surface finding and incomplete peer probe: findings=%+v err=%v", findings, err)
			}
		})
	}
}

// TestShadow_NothingListeningClean: every probed port answers closed or with
// an unrelated service. Checked-and-absent is a genuine clean result here -
// each probe received an answer, so nothing went untested.
func TestShadow_NothingListeningClean(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	unrelated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>totally normal site</html>"))
	}))
	defer unrelated.Close()

	withShadowPorts(t, portOf(unrelated.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings with no shadow surfaces, got %d: %+v", len(findings), findings)
	}
}

func TestShadow_ClosedPortIsClean(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	port := portOf(closed.URL)
	closed.Close()

	withShadowPorts(t, port)
	findings, err := runShadow(t, main.URL)
	if err != nil || len(findings) != 0 {
		t.Fatalf("closed port should be clean: findings=%+v err=%v", findings, err)
	}
}

func TestShadow_TransientResponsesAreInconclusive(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			main := httptest.NewServer(http.NotFoundHandler())
			defer main.Close()
			shadow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer shadow.Close()

			withShadowPorts(t, portOf(shadow.URL))
			findings, err := runShadow(t, main.URL)
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("transient responses must be incomplete: findings=%+v err=%v", findings, err)
			}
		})
	}
}

func TestShadow_FindingNotesOtherIncompletePort(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(shadowMCPHandler(false))
	defer shadow.Close()
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer limited.Close()

	withShadowPorts(t, portOf(shadow.URL), portOf(limited.URL))
	findings, err := runShadow(t, main.URL)
	if !errors.Is(err, attack.ErrInconclusive) || len(findings) != 1 ||
		!strings.Contains(err.Error(), strconv.Itoa(portOf(limited.URL))) {
		t.Fatalf("finding must retain the incomplete-port outcome: findings=%+v err=%v", findings, err)
	}
}

func TestShadow_CanceledProbeIsInconclusive(t *testing.T) {
	main := httptest.NewServer(http.NotFoundHandler())
	defer main.Close()
	shadow := httptest.NewServer(http.NotFoundHandler())
	defer shadow.Close()

	withShadowPorts(t, portOf(shadow.URL))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings, err := mcp.NewShadowSurfaceExecutor(shadowRC()).Execute(ctx, main.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("canceled probes must be incomplete: findings=%+v err=%v", findings, err)
	}
}

// TestShadow_TargetPortSkipped: the port named in the target URL belongs to
// whatever rule owns that surface directly. The executor must not re-report
// it as a shadow discovery.
func TestShadow_TargetPortSkipped(t *testing.T) {
	main := httptest.NewServer(shadowMCPHandler(false))
	defer main.Close()

	withShadowPorts(t, portOf(main.URL))
	findings, err := runShadow(t, main.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings: the target's own port must be skipped, got %d: %+v", len(findings), findings)
	}
}

func portOf(serverURL string) int {
	for i := len(serverURL) - 1; i >= 0; i-- {
		if serverURL[i] == ':' {
			out := 0
			for _, c := range serverURL[i+1:] {
				out = out*10 + int(c-'0')
			}
			return out
		}
	}
	panic("no port in " + serverURL)
}
