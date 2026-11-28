package mcp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

const fetchCanaryMarker = "batesian-canary-marker-2026"
const fetchCanaryPath = "/batesian-canary"

func fetchRobotsRule() attack.RuleContext {
	return attack.RuleContext{
		ID: "mcp-fetch-robots-001", Name: "MCP Fetch Robots Path Canonicalization",
		Severity: "low", Remediation: "Compare resolved paths before fetching.",
	}
}

func fetchTool() map[string]interface{} {
	tool := readOnlySchemaTool("fetch")
	schema := tool["inputSchema"].(map[string]interface{})
	schema["properties"] = map[string]interface{}{"url": map[string]interface{}{"type": "string"}}
	schema["required"] = []interface{}{"url"}
	return tool
}

func fetchCanaryServer(t *testing.T, served *atomic.Int32, auth *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		if r.Header.Get("Authorization") != "" {
			auth.Add(1)
		}
		switch r.URL.Path {
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: " + fetchCanaryPath + "\n"))
		case fetchCanaryPath, "/" + fetchCanaryPath:
			_, _ = w.Write([]byte(fetchCanaryMarker))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestFetchRobotsControlledProbe(t *testing.T) {
	for _, tc := range []struct {
		name, canonical, alternate string
		finding, incomplete        bool
	}{
		{"bypass", "robots", "marker", true, false},
		{"protected", "robots", "robots", false, false},
		{"no baseline denial", "network", "marker", false, true},
		{"alias failed", "robots", "network", false, true},
		{"error carrying marker", "robots", "error-marker", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var served, auth, called atomic.Int32
			origin := fetchCanaryServer(t, &served, &auth)
			defer origin.Close()
			server := &traversalServer{
				caps:  map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{fetchTool()},
				call: func(name string, args map[string]interface{}) (string, bool, string) {
					called.Add(1)
					if name != "fetch" || len(args) != 1 {
						t.Errorf("unexpected tool call: %s", name)
					}
					u, _ := args["url"].(string)
					if !strings.HasPrefix(u, origin.URL+fetchCanaryPath) && u != origin.URL+"/"+fetchCanaryPath {
						t.Errorf("unexpected URL")
					}
					posture := tc.canonical
					if u == origin.URL+"/"+fetchCanaryPath {
						posture = tc.alternate
					}
					switch posture {
					case "robots":
						return "The site's robots.txt says autonomous fetching is not allowed", true, ""
					case "marker":
						return fetchCanaryMarker, false, ""
					case "error-marker":
						return fetchCanaryMarker, true, ""
					default:
						return "connection failed", true, ""
					}
				},
			}
			target := httptest.NewServer(server.handler())
			defer target.Close()
			findings, err := mcp.NewFetchRobotsExecutor(fetchRobotsRule()).Execute(t.Context(), target.URL,
				attack.Options{TimeoutSeconds: 5, Token: "target-secret", MCPInvokeTools: []string{"fetch"},
					MCPFetchRobotsProbe: &attack.MCPFetchRobotsProbe{
						Origin: origin.URL, PrivatePath: fetchCanaryPath, PrivateMarker: fetchCanaryMarker,
					}})
			if tc.incomplete != errors.Is(err, attack.ErrInconclusive) || (len(findings) == 1) != tc.finding {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			if tc.finding && (findings[0].Confidence != attack.RiskIndicator ||
				strings.Contains(findings[0].Evidence, origin.URL) ||
				strings.Contains(findings[0].Evidence, fetchCanaryMarker)) {
				t.Fatalf("finding leaks canary or has wrong confidence: %+v", findings[0])
			}
			if served.Load() != 3 || auth.Load() != 0 {
				t.Fatalf("canary requests=%d authenticated=%d", served.Load(), auth.Load())
			}
			wantCalls := int32(2)
			if tc.canonical != "robots" {
				wantCalls = 1
			}
			if called.Load() != wantCalls {
				t.Fatalf("tool calls=%d want=%d", called.Load(), wantCalls)
			}
		})
	}
}

func TestFetchRobotsSelectedVariants(t *testing.T) {
	variants := []string{"backslash", "encoded_backslash", "path_parameter"}
	probe := &attack.MCPFetchRobotsProbe{
		PrivatePath: fetchCanaryPath, PrivateMarker: fetchCanaryMarker, Variants: variants,
	}
	for _, tc := range []struct {
		name             string
		posture          map[string]string
		finding, partial bool
	}{
		{"bypass", map[string]string{"backslash": "marker"}, true, false},
		{"protected", nil, false, false},
		{"partial", map[string]string{"backslash": "marker", "path_parameter": "network"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var originCalls, targetCalls atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originCalls.Add(1)
				if r.Header.Get("Authorization") != "" {
					t.Error("target credentials sent to canary")
				}
				if r.URL.Path == "/robots.txt" {
					_, _ = w.Write([]byte("User-agent: *\nDisallow: " + fetchCanaryPath + "\n"))
					return
				}
				_, _ = w.Write([]byte(fetchCanaryMarker))
			}))
			defer origin.Close()
			probe.Origin = origin.URL
			postures := map[string]string{origin.URL + fetchCanaryPath: "robots"}
			for _, alternate := range attack.FetchRobotsAlternates(probe) {
				posture := tc.posture[alternate.Variant]
				if posture == "" {
					posture = "robots"
				}
				postures[origin.URL+alternate.Path] = posture
			}
			server := &traversalServer{
				caps:  map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{fetchTool()},
				call: func(name string, args map[string]interface{}) (string, bool, string) {
					targetCalls.Add(1)
					if name != "fetch" || len(args) != 1 {
						t.Errorf("unexpected tool call: %s", name)
					}
					url, _ := args["url"].(string)
					switch postures[url] {
					case "robots":
						return "The site's robots.txt says autonomous fetching is not allowed", true, ""
					case "marker":
						return fetchCanaryMarker, false, ""
					case "network":
						return "connection failed", true, ""
					default:
						t.Errorf("unexpected URL: %s", url)
						return "", true, ""
					}
				},
			}
			target := httptest.NewServer(server.handler())
			defer target.Close()
			findings, err := mcp.NewFetchRobotsExecutor(fetchRobotsRule()).Execute(t.Context(), target.URL,
				attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"fetch"}, MCPFetchRobotsProbe: probe})
			if (len(findings) == 1) != tc.finding || errors.Is(err, attack.ErrInconclusive) != tc.partial ||
				originCalls.Load() != 5 || targetCalls.Load() != 4 {
				t.Fatalf("findings=%+v err=%v origin calls=%d tool calls=%d", findings, err, originCalls.Load(), targetCalls.Load())
			}
			if tc.finding && (!strings.Contains(findings[0].Evidence, "backslash") ||
				strings.Contains(findings[0].Evidence, origin.URL) || strings.Contains(findings[0].Evidence, fetchCanaryMarker)) {
				t.Fatalf("finding evidence: %s", findings[0].Evidence)
			}
		})
	}
}

func TestFetchRobotsRequiresApprovalAndValidCanary(t *testing.T) {
	var served, auth atomic.Int32
	origin := fetchCanaryServer(t, &served, &auth)
	defer origin.Close()
	probe := &attack.MCPFetchRobotsProbe{Origin: origin.URL, PrivatePath: fetchCanaryPath, PrivateMarker: fetchCanaryMarker}
	exec := mcp.NewFetchRobotsExecutor(fetchRobotsRule())
	_, err := exec.Execute(context.Background(), "https://mcp.example.com", attack.Options{MCPFetchRobotsProbe: probe})
	if !errors.Is(err, attack.ErrInconclusive) || served.Load() != 0 {
		t.Fatalf("without approval: err=%v requests=%d", err, served.Load())
	}
	probe.PrivatePath = "/private"
	_, err = exec.Execute(context.Background(), "https://mcp.example.com", attack.Options{
		MCPFetchRobotsProbe: probe, MCPInvokeTools: []string{"fetch"},
	})
	if !errors.Is(err, attack.ErrInconclusive) || served.Load() != 0 {
		t.Fatalf("invalid canary: err=%v requests=%d", err, served.Load())
	}
}

func TestFetchRobotsRejectsUnverifiedCanary(t *testing.T) {
	var targetCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nAllow: /\n"))
			return
		}
		_, _ = w.Write([]byte(fetchCanaryMarker))
	}))
	defer origin.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	_, err := mcp.NewFetchRobotsExecutor(fetchRobotsRule()).Execute(t.Context(), target.URL,
		attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"fetch"},
			MCPFetchRobotsProbe: &attack.MCPFetchRobotsProbe{
				Origin: origin.URL, PrivatePath: fetchCanaryPath, PrivateMarker: fetchCanaryMarker,
			}})
	if !errors.Is(err, attack.ErrInconclusive) || targetCalls.Load() != 0 {
		t.Fatalf("unverified canary: err=%v target requests=%d", err, targetCalls.Load())
	}
}

func TestFetchRobotsRejectsUnverifiedVariant(t *testing.T) {
	var targetCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: " + fetchCanaryPath + "\n"))
		case fetchCanaryPath:
			_, _ = w.Write([]byte(fetchCanaryMarker))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer origin.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	_, err := mcp.NewFetchRobotsExecutor(fetchRobotsRule()).Execute(t.Context(), target.URL,
		attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"fetch"},
			MCPFetchRobotsProbe: &attack.MCPFetchRobotsProbe{
				Origin: origin.URL, PrivatePath: fetchCanaryPath, PrivateMarker: fetchCanaryMarker,
				Variants: []string{"path_parameter"},
			}})
	if !errors.Is(err, attack.ErrInconclusive) || targetCalls.Load() != 0 {
		t.Fatalf("unverified variant: err=%v target requests=%d", err, targetCalls.Load())
	}
}
