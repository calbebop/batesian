package a2a_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/attack/a2a"
)

// tenantOf maps the bearer token to a tenant label for the multi-tenant fixtures.
func tenantOf(r *http.Request) string {
	switch r.Header.Get("Authorization") {
	case "Bearer tok-a":
		return "A"
	case "Bearer tok-b":
		return "B"
	default:
		return ""
	}
}

// tenantServer builds a two-tenant A2A test server. mode selects the posture:
//   - "vulnerable": authenticated GetTask ignores tenant ownership (cross reads leak)
//   - "secure":     GetTask returns a task only to its owning tenant
//   - "open":       no authentication at all (anyone creates and reads)
func tenantServer(mode string) *httptest.Server {
	var mu sync.Mutex
	owner := map[string]string{} // taskID -> owning tenant

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		req := readBody(r)
		method, _ := req["method"].(string)
		id := req["id"]
		params, _ := req["params"].(map[string]interface{})
		tenant := tenantOf(r)

		switch method {
		case "SendMessage", "message/send":
			if mode != "open" && tenant == "" {
				rpcErr(w, id, -32600, "authentication required") // creation is auth-gated
				return
			}
			tn := tenant
			if tn == "" {
				tn = "anon"
			}
			taskID := "task-" + tn + "-1"
			mu.Lock()
			owner[taskID] = tn
			mu.Unlock()
			taskResult(w, id, taskID, "ctx-"+tn)
		case "GetTask", "tasks/get":
			taskID, _ := params["id"].(string)
			mu.Lock()
			own := owner[taskID]
			mu.Unlock()
			switch mode {
			case "open":
				taskWithHistory(w, id, taskID, "ctx-"+own) // no auth at all
			case "secure":
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required")
					return
				}
				if tenant != own {
					rpcErr(w, id, -32001, "task not found") // tenant-bound
					return
				}
				taskWithHistory(w, id, taskID, "ctx-"+own)
			default: // vulnerable
				if tenant == "" {
					rpcErr(w, id, -32600, "authentication required") // auth enforced...
					return
				}
				taskWithHistory(w, id, taskID, "ctx-"+own) // ...but ownership IS NOT checked
			}
		default:
			rpcErr(w, id, -32601, "Method not found")
		}
	}))
}

func tenantPrincipals() []attack.Principal {
	return []attack.Principal{
		{Name: "tenant-a", Token: "tok-a", Tenant: "A"},
		{Name: "tenant-b", Token: "tok-b", Tenant: "B"},
	}
}

func mtOpts(principals ...attack.Principal) attack.Options {
	return attack.Options{TimeoutSeconds: 5, Principals: principals}
}

// TestMultiTenant_Vulnerable: authenticated GetTask ignores tenant ownership, so
// each tenant can read the other's task. The rule MUST fire (confirmed) in both
// directions.
func TestMultiTenant_Vulnerable(t *testing.T) {
	ts := tenantServer("vulnerable")
	defer ts.Close()

	findings, err := a2a.NewMultiTenantIsolationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected cross-tenant leak in both directions (2 findings), got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Confidence != attack.ConfirmedExploit {
			t.Errorf("want ConfirmedExploit, got %q", f.Confidence)
		}
		if f.Severity != "high" {
			t.Errorf("want high severity, got %q", f.Severity)
		}
		if len(f.Chain) != 3 || f.Chain[2].Outcome == "" {
			t.Errorf("expected a 3-hop provenance chain, got %+v", f.Chain)
		}
	}
}

// TestMultiTenant_Secure: GetTask is tenant-bound (cross reads rejected -32001).
// The rule MUST stay silent.
func TestMultiTenant_Secure(t *testing.T) {
	ts := tenantServer("secure")
	defer ts.Close()

	findings, err := a2a.NewMultiTenantIsolationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against tenant-bound server, got %d: %+v", len(findings), findings)
	}
}

// TestMultiTenant_OpenServerIsNotIsolationBreach: the server enforces no auth at
// all, so an unauthenticated read of A's task succeeds. That is task-idor / open
// territory, not a tenant-isolation breach. The rule MUST stay silent (the
// open-server discriminator suppresses it).
func TestMultiTenant_OpenServerIsNotIsolationBreach(t *testing.T) {
	ts := tenantServer("open")
	defer ts.Close()

	findings, err := a2a.NewMultiTenantIsolationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings against a fully-open server, got %d: %+v", len(findings), findings)
	}
}

// TestMultiTenant_RequiresTwoPrincipals: with fewer than two principals the rule
// cannot establish two tenants and MUST clean-skip.
func TestMultiTenant_RequiresTwoPrincipals(t *testing.T) {
	ts := tenantServer("vulnerable")
	defer ts.Close()

	findings, err := a2a.NewMultiTenantIsolationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(tenantPrincipals()[:1]...))
	// A rule that sends no packets has not tested anything. This used to assert
	// err == nil, which under the project's convention means "tested, and the target
	// is secure" - about a deliberately vulnerable fixture, with zero requests sent.
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("one principal cannot exercise a cross-principal rule; want ErrInconclusive, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
}

// TestMultiTenant_SameTokenSkips: two principals sharing a token are the same
// identity and cannot demonstrate isolation; the rule MUST clean-skip.
func TestMultiTenant_SameTokenSkips(t *testing.T) {
	ts := tenantServer("vulnerable")
	defer ts.Close()

	same := []attack.Principal{
		{Name: "tenant-a", Token: "tok-a", Tenant: "A"},
		{Name: "tenant-b", Token: "tok-a", Tenant: "B"},
	}
	findings, err := a2a.NewMultiTenantIsolationExecutor(testRuleCtx()).
		Execute(context.Background(), ts.URL, mtOpts(same...))
	if !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("two principals sharing a token are one identity, so there is no boundary to "+
			"cross; want ErrInconclusive, got %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(findings))
	}
}
