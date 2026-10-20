package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func omRuleCtx() attack.RuleContext {
	return attack.RuleContext{ID: "mcp-oauth-metadata-ssrf-001", Name: "MCP OAuth DCR Metadata Fetch", Severity: "high", Remediation: "Restrict metadata fetch destinations."}
}

// metadataSSRFServer models an OAuth authorization server with a DCR endpoint.
// mode controls behaviour on registration:
//   - "fetch":   fetches the registrant-supplied jwks_uri
//   - "fetch-reject": fetches jwks_uri, then rejects registration
//   - "nofetch": stores metadata without fetching (safe)
//   - "no-oauth": serves no authorization-server metadata
//   - "fetch-managed": as "fetch", and implements RFC 7592 client management
//
// deleted, when non-nil, receives each client_id the server deregisters.
func metadataSSRFServerManaged(mode string, deleted *[]string) *httptest.Server {
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	if mode == "fetch-managed" {
		mux.HandleFunc("/register/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if deleted != nil {
				*deleted = append(*deleted, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		if mode == "no-oauth" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                ts.URL,
			"registration_endpoint": ts.URL + "/register",
		})
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)

		if mode == "fetch" || mode == "fetch-managed" || mode == "fetch-reject" {
			if u, _ := body["jwks_uri"].(string); u != "" {
				// VULNERABLE: fetch the registrant-supplied URL server-side.
				c := &http.Client{Timeout: 3 * time.Second}
				if req, err := http.NewRequest(http.MethodGet, u, nil); err == nil {
					if resp, err := c.Do(req); err == nil {
						_ = resp.Body.Close()
					}
				}
			}
		}
		out := map[string]interface{}{"client_id": "c-123", "client_name": body["client_name"]}
		if mode == "fetch-reject" || mode == "reject" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if mode == "fetch-managed" {
			out["registration_client_uri"] = ts.URL + "/register/c-123"
			out["registration_access_token"] = "rat-c-123"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(out)
	})

	return ts
}

// metadataSSRFServer keeps the original signature for the tests that do not care
// about client management.
func metadataSSRFServer(mode string) *httptest.Server {
	return metadataSSRFServerManaged(mode, nil)
}

func runMetadataSSRF(t *testing.T, ts *httptest.Server) []attack.Finding {
	t.Helper()
	findings, err := mcpattack.NewOAuthMetadataSSRFExecutor(omRuleCtx()).Execute(context.Background(), ts.URL, attack.Options{TimeoutSeconds: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return findings
}

func assertMetadataCallbackGrade(t *testing.T, finding attack.Finding) {
	t.Helper()
	const prefix = "Callback destination: "
	_, destination, ok := strings.Cut(finding.Evidence, prefix)
	if !ok {
		t.Fatalf("callback destination missing: %+v", finding)
	}
	destination, _, _ = strings.Cut(destination, "\n")
	u, err := url.Parse(destination)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(u.Hostname())
	private := ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
	if private {
		if finding.Severity != "high" || finding.Confidence != attack.ConfirmedExploit ||
			!strings.Contains(finding.Description, "this private address") {
			t.Fatalf("private callback undergraded: %+v", finding)
		}
	} else if finding.Severity != "info" || finding.Confidence != attack.RiskIndicator ||
		strings.Contains(finding.Title, "private") {
		t.Fatalf("public callback overstated: %+v", finding)
	}
}

func TestMetadataSSRF_Fetch(t *testing.T) {
	ts := metadataSSRFServer("fetch")
	defer ts.Close()

	findings := runMetadataSSRF(t, ts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	assertMetadataCallbackGrade(t, f)
}

func TestMetadataSSRF_FetchThenReject(t *testing.T) {
	ts := metadataSSRFServer("fetch-reject")
	defer ts.Close()
	findings := runMetadataSSRF(t, ts)
	if len(findings) != 1 ||
		!strings.Contains(findings[0].Evidence, "Registration status: HTTP 400") ||
		!strings.Contains(findings[0].Evidence, "Fetched field: jwks_uri") {
		t.Fatalf("fetch before rejection was missed: %+v", findings)
	}
	assertMetadataCallbackGrade(t, findings[0])
}

func TestMetadataSSRF_RejectWithoutCallbackIsIncomplete(t *testing.T) {
	ts := metadataSSRFServer("reject")
	defer ts.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	findings, err := mcpattack.NewOAuthMetadataSSRFExecutor(omRuleCtx()).Execute(ctx, ts.URL, testOpts())
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("rejected registration without a callback: findings=%+v err=%v", findings, err)
	}
}

func TestMetadataSSRF_NoCallbackIsIncomplete(t *testing.T) {
	ts := metadataSSRFServer("nofetch")
	defer ts.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	findings, err := mcpattack.NewOAuthMetadataSSRFExecutor(omRuleCtx()).Execute(ctx, ts.URL, attack.Options{TimeoutSeconds: 5})
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("unobserved callback must be incomplete, got findings=%+v err=%v", findings, err)
	}
	if !strings.Contains(err.Error(), "callback") {
		t.Errorf("skip reason should identify the missing callback: %v", err)
	}
}

func TestMetadataSSRF_ExternalOOBNeedsVerification(t *testing.T) {
	ts := metadataSSRFServer("nofetch")
	defer ts.Close()
	state := &attack.TargetState{}

	findings, err := mcpattack.NewOAuthMetadataSSRFExecutor(omRuleCtx()).Execute(t.Context(), ts.URL, attack.Options{
		TimeoutSeconds: 5,
		OOBListenerURL: "http://oob.batesian.invalid",
		TargetState:    state,
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("external callbacks need manual verification, got findings=%+v err=%v", findings, err)
	}
	if findings[0].Severity != "info" || findings[0].Confidence != attack.RiskIndicator {
		t.Errorf("external OOB should remain an unverified indicator: %+v", findings[0])
	}
	objects := state.Snapshot()
	if len(objects) != 1 || objects[0].Cleanup != attack.CleanupNotAttempted ||
		!strings.Contains(findings[0].Evidence, "cleanup not attempted") {
		t.Errorf("external OOB client disposition was hidden: objects=%+v evidence=%s", objects, findings[0].Evidence)
	}
}

// TestMetadataSSRF_NoOAuth: no DCR endpoint => clean skip.
// A reachable MCP server with no DCR advertisement is not applicable: clean.
func TestMetadataSSRF_NoOAuth(t *testing.T) {
	ts, _ := mountedMCPServer(t)
	defer ts.Close()

	if findings := runMetadataSSRF(t, ts); len(findings) != 0 {
		t.Errorf("expected zero findings against a non-OAuth MCP server, got %d", len(findings))
	}
}

func TestMetadataSSRF_NothingReachableIsNotTested(t *testing.T) {
	ts := metadataSSRFServer("no-oauth") // 404s the metadata and everything else
	defer ts.Close()

	_, err := mcpattack.NewOAuthMetadataSSRFExecutor(omRuleCtx()).
		Execute(context.Background(), ts.URL, testOpts())
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("expected ErrInconclusive when nothing answered, got err=%v", err)
	}
}

// This rule's payload IS the registration, so the client cannot be removed until the
// OOB wait is over: deleting it first risks cancelling the very fetch being listened
// for. Both halves are asserted here, because getting the order wrong would trade a
// real finding for a tidier target and the finding is the point.
func TestMetadataSSRF_ClientRemovedWithoutLosingTheFinding(t *testing.T) {
	var deleted []string
	ts := metadataSSRFServerManaged("fetch-managed", &deleted)
	defer ts.Close()

	findings := runMetadataSSRF(t, ts)
	if len(findings) != 1 {
		t.Fatalf("cleanup must not cost the finding, got %d: %+v", len(findings), findings)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected the registered client to be deleted once, saw %d: %v", len(deleted), deleted)
	}
	if !strings.Contains(findings[0].Evidence, "deleted afterwards via RFC 7592") {
		t.Errorf("the finding should record the cleanup; got:\n%s", findings[0].Evidence)
	}
}
