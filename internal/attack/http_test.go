package attack_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestNewUnauthHTTPClient_StripsToken(t *testing.T) {
	opts := attack.Options{
		Token:          "super-secret",
		TimeoutSeconds: 30,
		SkipTLS:        true,
	}
	vars := attack.NewVars("https://example.com", "")

	c := attack.NewUnauthHTTPClient(opts, vars)

	if attack.TokenOf(c) != "" {
		t.Errorf("NewUnauthHTTPClient: expected empty token, got %q", attack.TokenOf(c))
	}
}

func TestNewHTTPClient_PreservesToken(t *testing.T) {
	opts := attack.Options{
		Token:          "my-token",
		TimeoutSeconds: 10,
	}
	vars := attack.NewVars("https://example.com", "")

	c := attack.NewHTTPClient(opts, vars)

	if attack.TokenOf(c) != "my-token" {
		t.Errorf("NewHTTPClient: expected token %q, got %q", "my-token", attack.TokenOf(c))
	}
}

// TestUserAgent_IncludesVersion verifies the User-Agent header reflects
// attack.Version so support / supportability of bug reports stays accurate.
func TestUserAgent_IncludesVersion(t *testing.T) {
	prev := attack.Version
	attack.Version = "0.99.0-test"
	t.Cleanup(func() { attack.Version = prev })

	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := attack.NewHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(srv.URL, ""))
	if _, err := c.GET(context.Background(), srv.URL, nil); err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if !strings.Contains(seen, "batesian/0.99.0-test") {
		t.Errorf("expected User-Agent to contain batesian/0.99.0-test, got %q", seen)
	}
}

// TestResponseContainsAny_SkipsEmptySubstring guards against the empty-needle
// false positive: strings.Contains(body, "") is always true, so an optional,
// absent value (e.g. a missing contextId) must not match any body.
func TestResponseContainsAny_SkipsEmptySubstring(t *testing.T) {
	r := &attack.Response{Body: []byte(`{"jsonrpc":"2.0","result":null}`)}

	if r.ContainsAny("") {
		t.Error(`ContainsAny("") matched; empty needle must be skipped`)
	}
	if r.ContainsAny("", "absent") {
		t.Error(`ContainsAny("", "absent") matched; neither needle is present`)
	}
	if !r.ContainsAny("", "result") {
		t.Error(`ContainsAny("", "result") did not match a present non-empty needle`)
	}
}
