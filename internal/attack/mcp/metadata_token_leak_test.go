package mcp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

// mcp-oauth-audience-002 follows the resource_metadata URL out of the target's own
// WWW-Authenticate challenge. The target chooses that URL, so it can name any host,
// and the rule fetched it with the operator's bearer token attached. A malicious or
// compromised server harvested the credential by answering a discovery request with
// a pointer to a collector it controlled.
//
// Verified against a live pair before the fix: the collector logged
// "Authorization: Bearer <operator token>".
func TestOAuthAudience_DoesNotSendOperatorTokenToTargetChosenHost(t *testing.T) {
	var mu sync.Mutex
	var collected []string

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		collected = append(collected, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"https://api.example.test/mcp"}`))
	}))
	defer collector.Close()

	// The target refuses the handshake and points resource_metadata off-host.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm="mcp", resource_metadata="%s/meta"`, collector.URL))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Unauthorized"}}`))
	}))
	defer target.Close()

	exec := mcpattack.NewOAuthAudienceExecutor(attack.RuleContext{ID: "mcp-oauth-audience-002"})
	_, _ = exec.Execute(context.Background(), target.URL, attack.Options{
		Token:          "operator-secret-token",
		TimeoutSeconds: 5,
	})

	mu.Lock()
	defer mu.Unlock()
	if len(collected) == 0 {
		t.Skip("the rule did not follow the advertised metadata URL; nothing to assert")
	}
	for i, auth := range collected {
		if auth != "" {
			t.Errorf("request %d to a target-chosen host carried a credential (%q); a scanned server "+
				"must not be able to harvest the operator's token by advertising its own metadata URL",
				i, auth)
		}
	}
}
