package mcp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcp "github.com/calbebop/batesian/internal/attack/mcp"
)

const fetchRedirectPath = "/batesian-entry"

func fetchRobotsRedirectRule() attack.RuleContext {
	return attack.RuleContext{
		ID: "mcp-fetch-robots-redirect-001", Name: "MCP Fetch Robots Redirect Enforcement",
		Severity: "low", Remediation: "Check each redirect destination against robots policy.",
	}
}

func TestFetchRobotsRedirectControlledProbe(t *testing.T) {
	for _, tc := range []struct {
		name, canonical, redirect string
		finding, incomplete       bool
	}{
		{"bypass", "robots", "marker", true, false},
		{"protected", "robots", "target-robots", false, false},
		{"unrelated error", "robots", "network", false, true},
		{"source denial", "robots", "robots", false, true},
		{"error carrying marker", "robots", "error-marker", false, true},
		{"no direct denial", "network", "marker", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var originCalls, authenticated, toolCalls atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				originCalls.Add(1)
				if r.Header.Get("Authorization") != "" {
					authenticated.Add(1)
				}
				switch r.URL.Path {
				case "/robots.txt":
					_, _ = w.Write([]byte("User-agent: *\nDisallow: " + fetchCanaryPath + "\n"))
				case fetchCanaryPath:
					_, _ = w.Write([]byte(fetchCanaryMarker))
				case fetchRedirectPath:
					w.Header().Set("Location", fetchCanaryPath)
					w.WriteHeader(http.StatusFound)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer origin.Close()
			server := &traversalServer{
				caps:  map[string]interface{}{"tools": map[string]interface{}{}},
				tools: []map[string]interface{}{fetchTool()},
				call: func(name string, args map[string]interface{}) (string, bool, string) {
					toolCalls.Add(1)
					if name != "fetch" || len(args) != 1 {
						t.Errorf("unexpected tool call: %s", name)
					}
					url, _ := args["url"].(string)
					posture := tc.canonical
					if url == origin.URL+fetchRedirectPath {
						posture = tc.redirect
					} else if url != origin.URL+fetchCanaryPath {
						t.Errorf("unexpected URL: %s", url)
					}
					switch posture {
					case "robots":
						return "The site's robots.txt says autonomous fetching is not allowed", true, ""
					case "target-robots":
						return "The site's robots.txt says autonomous fetching of " + origin.URL + fetchCanaryPath + " is not allowed", true, ""
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
			findings, err := mcp.NewFetchRobotsRedirectExecutor(fetchRobotsRedirectRule()).Execute(t.Context(), target.URL,
				attack.Options{TimeoutSeconds: 5, Token: "target-secret", MCPInvokeTools: []string{"fetch"},
					MCPFetchRobotsRedirectProbe: &attack.MCPFetchRobotsRedirectProbe{
						Origin: origin.URL, PrivatePath: fetchCanaryPath,
						PrivateMarker: fetchCanaryMarker, RedirectPath: fetchRedirectPath,
					}})
			if (len(findings) == 1) != tc.finding || errors.Is(err, attack.ErrInconclusive) != tc.incomplete {
				t.Fatalf("findings=%+v err=%v", findings, err)
			}
			if originCalls.Load() != 3 || authenticated.Load() != 0 {
				t.Fatalf("origin requests=%d authenticated=%d", originCalls.Load(), authenticated.Load())
			}
			wantCalls := int32(2)
			if tc.canonical != "robots" {
				wantCalls = 1
			}
			if toolCalls.Load() != wantCalls {
				t.Fatalf("tool calls=%d want=%d", toolCalls.Load(), wantCalls)
			}
			if tc.finding && (findings[0].Confidence != attack.RiskIndicator ||
				strings.Contains(findings[0].Evidence, origin.URL) ||
				strings.Contains(findings[0].Evidence, fetchCanaryMarker)) {
				t.Fatalf("finding leaks canary or has wrong confidence: %+v", findings[0])
			}
		})
	}
}

func TestFetchRobotsRedirectRequiresApproval(t *testing.T) {
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer origin.Close()
	probe := &attack.MCPFetchRobotsRedirectProbe{
		Origin: origin.URL, PrivatePath: fetchCanaryPath,
		PrivateMarker: fetchCanaryMarker, RedirectPath: fetchRedirectPath,
	}
	_, err := mcp.NewFetchRobotsRedirectExecutor(fetchRobotsRedirectRule()).Execute(t.Context(),
		"https://mcp.example.com", attack.Options{MCPFetchRobotsRedirectProbe: probe})
	if !errors.Is(err, attack.ErrInconclusive) || originCalls.Load() != 0 {
		t.Fatalf("without approval: err=%v origin requests=%d", err, originCalls.Load())
	}
}

func TestFetchRobotsRedirectRejectsUnverifiedOrigin(t *testing.T) {
	var targetCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: " + fetchCanaryPath + "\n"))
		case fetchCanaryPath:
			_, _ = w.Write([]byte(fetchCanaryMarker))
		case fetchRedirectPath:
			w.Header().Set("Location", "https://other.example.com/private")
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer origin.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	_, err := mcp.NewFetchRobotsRedirectExecutor(fetchRobotsRedirectRule()).Execute(t.Context(), target.URL,
		attack.Options{TimeoutSeconds: 5, MCPInvokeTools: []string{"fetch"},
			MCPFetchRobotsRedirectProbe: &attack.MCPFetchRobotsRedirectProbe{
				Origin: origin.URL, PrivatePath: fetchCanaryPath,
				PrivateMarker: fetchCanaryMarker, RedirectPath: fetchRedirectPath,
			}})
	if !errors.Is(err, attack.ErrInconclusive) || targetCalls.Load() != 0 {
		t.Fatalf("unverified redirect: err=%v target requests=%d", err, targetCalls.Load())
	}
}
