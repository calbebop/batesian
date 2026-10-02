package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/protocol/a2a"
	"github.com/calbebop/batesian/internal/report"
)

// TestCardToProbeResult_ExtendedCardAndProtocol covers the two card fields whose
// v0.3 spellings probe could not see. ExtendedCardAvailable is not merely a
// printed row: probe gates two live checks of /extendedAgentCard on it, one of
// which fetches the endpoint with a fabricated Bearer token, so a v0.3 agent got
// neither.
func TestCardToProbeResult_ExtendedCardAndProtocol(t *testing.T) {
	tests := []struct {
		name         string
		fields       string
		wantExtended bool
		wantProtocol string
		why          string
	}{
		{
			name:         "v0.3 card",
			fields:       `"protocolVersion":"0.3.0","supportsAuthenticatedExtendedCard":true`,
			wantExtended: true,
			wantProtocol: "0.3.0",
			why:          "this is what a2a-go serves, and probe skipped both extended-card checks",
		},
		{
			name:         "v1.0 card",
			fields:       `"protocolVersion":"1.0","capabilities":{"extendedAgentCard":true}`,
			wantExtended: true,
			wantProtocol: "1.0",
			why:          "the v1.0 path must be unaffected",
		},
		{
			name:         "no extended card, no protocol declared",
			fields:       `"capabilities":{"streaming":true}`,
			wantExtended: false,
			wantProtocol: "",
			why:          "probe must not claim an extended card that was never advertised",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"name":"Agent","description":"d","version":"9.9.9","url":"http://127.0.0.1:1/",` +
				`"preferredTransport":"JSONRPC","skills":[],` + tt.fields + `}`
			var card a2a.AgentCard
			if err := json.Unmarshal([]byte(body), &card); err != nil {
				t.Fatalf("card must parse: %v", err)
			}

			got := cardToProbeResult(&card, time.Millisecond)
			if got.ExtendedCardAvailable != tt.wantExtended {
				t.Errorf("ExtendedCardAvailable = %v, want %v (%s)",
					got.ExtendedCardAvailable, tt.wantExtended, tt.why)
			}
			if got.ProtocolVersion != tt.wantProtocol {
				t.Errorf("ProtocolVersion = %q, want %q", got.ProtocolVersion, tt.wantProtocol)
			}
			// The agent version and the protocol version are different things and
			// must not be conflated in the output.
			if got.Version != "9.9.9" {
				t.Errorf("Version = %q, want the agent version 9.9.9", got.Version)
			}
		})
	}
}

// The Authentication block probe prints is built here, so this is where a
// regression in what it reads would show up. The unit tests on AgentCard cover
// the card semantics; these cover that cardToProbeResult actually asks the card
// rather than reaching for one version's field.
func TestCardToProbeResult_AuthAcrossCardVersions(t *testing.T) {
	tests := []struct {
		name           string
		security       string
		wantAuth       bool
		wantSchemeText string
		why            string
	}{
		{
			name: "v0.3 card, native shape",
			security: `"security":[{"bearerAuth":["a2a:invoke"]}],` +
				`"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer","bearerFormat":"opaque"}}`,
			wantAuth:       true,
			wantSchemeText: "bearerAuth (http/bearer)",
			why:            "this is what the official Go SDK serves, and probe reported it as unauthenticated",
		},
		{
			name: "v1.0 card, native shape",
			security: `"securityRequirements":[{"schemes":{"bearerAuth":{"list":["a2a:invoke"]}}}],` +
				`"securitySchemes":{"bearerAuth":{"httpAuthSecurityScheme":{"scheme":"bearer"}}}`,
			wantAuth:       true,
			wantSchemeText: "bearerAuth (http/bearer)",
			why:            "the v1.0 path must be unaffected",
		},
		{
			name:     "no security declared",
			security: `"description2":"none"`,
			wantAuth: false,
			why:      "an agent declaring nothing is reported as unauthenticated, which is accurate",
		},
		{
			name:     "v0.3 card permitting anonymous access",
			security: `"security":[{},{"bearerAuth":[]}]`,
			wantAuth: false,
			why:      "an empty requirement object explicitly permits anonymous access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"name":"Agent","description":"d","version":"1.0.0","url":"http://127.0.0.1:1/",` +
				`"preferredTransport":"JSONRPC","capabilities":{},"skills":[],` + tt.security + `}`
			var card a2a.AgentCard
			if err := json.Unmarshal([]byte(body), &card); err != nil {
				t.Fatalf("card must parse: %v", err)
			}

			got := cardToProbeResult(&card, time.Millisecond)
			if got.AuthRequired != tt.wantAuth {
				t.Errorf("AuthRequired = %v, want %v (%s)", got.AuthRequired, tt.wantAuth, tt.why)
			}
			if tt.wantSchemeText == "" {
				return
			}
			joined := strings.Join(got.SecuritySchemes, ", ")
			if joined != tt.wantSchemeText {
				t.Errorf("SecuritySchemes = %q, want %q", joined, tt.wantSchemeText)
			}
		})
	}
}

// Two probes of an unchanged agent must print the same Schemes row.
//
// SecuritySchemes is a map and Go randomizes map iteration, so the row order used
// to vary between runs. Repetition is what makes this reliable: the first six live
// runs against a four-scheme card all agreed by chance, and only at twenty did
// three distinct orderings appear. Go shuffles the start offset within a bucket, so
// a small map yields rotations of one sequence and a short sample easily misses it.
func TestCardToProbeResult_SchemeOrderIsDeterministic(t *testing.T) {
	const card = `{
		"name": "Multi-Scheme Agent", "description": "d", "version": "1.0.0",
		"capabilities": {}, "skills": [],
		"securitySchemes": {
			"bearerAuth": {"httpAuthSecurityScheme": {"scheme": "bearer"}},
			"apiKeyAuth": {"apiKeySecurityScheme": {"location": "header", "name": "X-API-Key"}},
			"oauth2Auth": {"oauth2SecurityScheme": {"flows": {}}},
			"mtlsAuth": {"mtlsSecurityScheme": {}},
			"oidcAuth": {"openIdConnectSecurityScheme": {"openIdConnectUrl": "https://idp/.well-known/openid-configuration"}}
		}
	}`

	var first []string
	for run := 0; run < 50; run++ {
		var c a2a.AgentCard
		if err := json.Unmarshal([]byte(card), &c); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got := cardToProbeResult(&c, time.Millisecond).SecuritySchemes
		if len(got) != 5 {
			t.Fatalf("run %d: expected 5 schemes, got %d: %v", run, len(got), got)
		}
		if run == 0 {
			first = got
			continue
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("run %d printed a different scheme order than run 0; two probes of an unchanged agent must match: first=%v now=%v",
					run, first, got)
			}
		}
	}
	if !sort.StringsAreSorted(first) {
		t.Errorf("schemes should be in a stable, predictable order, got %v", first)
	}
}

// Probe ran on context.Background() while main installs signal.NotifyContext,
// which removes the default SIGINT kill. A stalled target therefore made probe
// unkillable: the first and second Ctrl+C did nothing and the process hung
// until the request timeout elapsed. The command's context must reach the
// wire, and both protocol clients bind it via NewRequestWithContext.
func TestProbeA2A_ContextCancellationInterruptsStalledFetch(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // the target accepted the connection and never answers
	}))
	// Defers run LIFO: close(release) is registered last, so it runs before
	// Server.Close, or Close waits on the stalled handler forever.
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := probeA2A(ctx, srv.URL, "", 30*time.Second, false, "", report.FormatTable, report.New(io.Discard, false))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a stalled target, got nil")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("probe returned after %s; cancellation must interrupt the fetch, not wait out the 30s request timeout", elapsed)
	}
}

// Same contract, MCP side: the initialize handshake is the first wire request,
// so cancellation must unblock it.
func TestProbeMCP_ContextCancellationInterruptsInitialize(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // every candidate endpoint stalls
	}))
	// Defers run LIFO: close(release) is registered last, so it runs before
	// Server.Close, or Close waits on the stalled handler forever.
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := probeMCP(ctx, srv.URL, "", 30*time.Second, false, "", report.FormatTable, report.New(io.Discard, false))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a stalled target, got nil")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("probe returned after %s; cancellation must interrupt initialize, not wait out the 30s request timeout", elapsed)
	}
}

func TestProbeA2A_TokenDoesNotTurnExtendedCardCheckIntoAuthenticatedRequest(t *testing.T) {
	var mu sync.Mutex
	var cardAuth string
	var extAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case a2a.WellKnownPath:
			mu.Lock()
			cardAuth = r.Header.Get("Authorization")
			mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer valid" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"name":"Agent","version":"1","capabilities":{"extendedAgentCard":true},"skills":[]}`)
		case a2a.ExtendedCardPath:
			mu.Lock()
			extAuth = append(extAuth, r.Header.Get("Authorization"))
			mu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	if err := probeA2A(context.Background(), srv.URL, "valid", time.Second, false, "", report.FormatTable, report.New(&out, false)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "a2a-extcard-unauth-001") {
		t.Fatalf("authenticated card access was reported as an anonymous disclosure:\n%s", out.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if cardAuth != "Bearer valid" {
		t.Errorf("card fetch Authorization = %q", cardAuth)
	}
	if len(extAuth) != 2 || extAuth[0] != "" || extAuth[1] != "Bearer batesian-invalid-probe-token" {
		t.Errorf("extended card Authorization headers = %q", extAuth)
	}
}

func TestProbeA2A_TokenStillFlagsAnonymousExtendedCard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case a2a.WellKnownPath:
			if r.Header.Get("Authorization") != "Bearer valid" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"name":"Agent","version":"1","capabilities":{"extendedAgentCard":true},"skills":[]}`)
		case a2a.ExtendedCardPath:
			if r.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"name":"Extended Agent","description":"Private capabilities","version":"1","supportedInterfaces":[{"url":"https://agent.example.com","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"capabilities":{},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	if err := probeA2A(context.Background(), srv.URL, "valid", time.Second, false, "", report.FormatTable, report.New(&out, false)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "a2a-extcard-unauth-001") {
		t.Fatalf("anonymous extended card was not flagged:\n%s", out.String())
	}
}

func TestProbeA2A_GenericExtendedCardResponseNotFlagged(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"name":"Agent"}`, `<html>login</html>`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case a2a.WellKnownPath:
					_, _ = io.WriteString(w, `{"name":"Agent","version":"1","capabilities":{"extendedAgentCard":true},"skills":[]}`)
				case a2a.ExtendedCardPath:
					_, _ = io.WriteString(w, body)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			var out bytes.Buffer
			if err := probeA2A(t.Context(), srv.URL, "", time.Second, false, "", report.FormatTable, report.New(&out, false)); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "a2a-extcard-unauth-001") {
				t.Fatalf("generic response was reported as an extended card:\n%s", out.String())
			}
		})
	}
}

func TestProbeMCP_ResourceFlagUsesSeparateAnonymousSession(t *testing.T) {
	for _, tc := range []struct {
		name          string
		token         string
		anonInit      bool
		anonResources bool
		wantFlag      bool
	}{
		{"auth-gated", "valid", false, false, false},
		{"session-gated", "valid", true, false, false},
		{"open-with-token", "valid", true, true, true},
		{"open-without-token", "", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var call struct {
					Method string `json:"method"`
				}
				if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
					t.Errorf("decode request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				authed := r.Header.Get("Authorization") == "Bearer valid"
				switch call.Method {
				case "initialize":
					if !authed && !tc.anonInit {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					sessionID := "anonymous"
					if authed {
						sessionID = "authenticated"
					}
					w.Header().Set("Mcp-Session-Id", sessionID)
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"server","version":"1"},"capabilities":{"resources":{}}}}`)
				case "resources/list":
					id := r.Header.Get("Mcp-Session-Id")
					if id == "authenticated" || (id == "anonymous" && tc.anonResources) {
						_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":11,"result":{"resources":[{"uri":"file:///private"}]}}`)
						return
					}
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":11,"result":{"resources":[]}}`)
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			var out bytes.Buffer
			if err := probeMCP(context.Background(), srv.URL+"/mcp", tc.token, time.Second, false, "", report.FormatTable, report.New(&out, false)); err != nil {
				t.Fatal(err)
			}
			gotFlag := strings.Contains(out.String(), "mcp-resources-unauth-001")
			if gotFlag != tc.wantFlag {
				t.Errorf("unauthenticated resource flag = %v, want %v:\n%s", gotFlag, tc.wantFlag, out.String())
			}
			if !strings.Contains(out.String(), "Resources (1)") {
				t.Errorf("resource surface was not enumerated:\n%s", out.String())
			}
		})
	}
}
