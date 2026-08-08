package attack_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

// authRecorder is a server that records the Authorization header of every request.
func authRecorder(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"https://example.test/mcp"}`))
	}))
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(seen))
		copy(out, seen)
		return out
	}
}

// The operator's credential is issued for one target. Several rules follow URLs the
// TARGET supplies: the resource_metadata parameter of its own WWW-Authenticate
// challenge, a registration_endpoint from its OAuth metadata. A target that names
// another host must not receive the token by asking for it.
func TestHTTPClient_TokenNotSentOffHost(t *testing.T) {
	thirdParty, thirdPartyAuths := authRecorder(t)
	defer thirdParty.Close()
	target, targetAuths := authRecorder(t)
	defer target.Close()

	opts := attack.Options{Token: "operator-secret", TimeoutSeconds: 5}
	client := attack.NewHTTPClient(opts, attack.NewVars(target.URL, ""))

	if _, err := client.GET(context.Background(), target.URL+"/mcp", nil); err != nil {
		t.Fatalf("GET target: %v", err)
	}
	if _, err := client.GET(context.Background(), thirdParty.URL+"/meta", nil); err != nil {
		t.Fatalf("GET third party: %v", err)
	}

	got := targetAuths()
	if len(got) != 1 || got[0] != "Bearer operator-secret" {
		t.Errorf("the target should receive the operator token, got %q", got)
	}
	if off := thirdPartyAuths(); len(off) != 1 || off[0] != "" {
		t.Errorf("a host other than the scan target must not receive the operator token, got %q", off)
	}
}

// An explicit Authorization header is an author stating intent (a principal token,
// a deliberately forged token), not ambient injection, so the guard leaves it
// alone. Rules like a2a-peer-impersonation depend on this.
func TestHTTPClient_ExplicitAuthorizationSurvivesOffHost(t *testing.T) {
	thirdParty, auths := authRecorder(t)
	defer thirdParty.Close()

	opts := attack.Options{Token: "operator-secret", TimeoutSeconds: 5}
	client := attack.NewHTTPClient(opts, attack.NewVars("http://target.invalid", ""))

	_, err := client.GET(context.Background(), thirdParty.URL+"/x",
		map[string]string{"Authorization": "Bearer deliberate-choice"})
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if got := auths(); len(got) != 1 || got[0] != "Bearer deliberate-choice" {
		t.Errorf("an explicitly set Authorization header must be sent as written, got %q", got)
	}
}

// Sub-paths and differing paths on the target host are still the target.
func TestHTTPClient_TokenSentAcrossPathsOnTargetHost(t *testing.T) {
	target, auths := authRecorder(t)
	defer target.Close()

	opts := attack.Options{Token: "operator-secret", TimeoutSeconds: 5}
	// Target given as a sub-path, which is how the OAuth fixtures are scanned.
	client := attack.NewHTTPClient(opts, attack.NewVars(target.URL+"/vulnerable/mcp", ""))

	for _, p := range []string{"/mcp", "/.well-known/oauth-protected-resource", "/api"} {
		if _, err := client.GET(context.Background(), target.URL+p, nil); err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
	}
	for i, a := range auths() {
		if a != "Bearer operator-secret" {
			t.Errorf("request %d to the target host should carry the token, got %q", i, a)
		}
	}
}
