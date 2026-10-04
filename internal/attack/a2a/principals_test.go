package a2a

import (
	"errors"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestTwoPrincipals(t *testing.T) {
	t.Run("none configured", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("want ErrInconclusive, got %v", err)
		}
		if !strings.Contains(err.Error(), "--principal") {
			t.Errorf("the reason should tell the operator how to make the rule run, got: %v", err)
		}
	})

	t.Run("only one configured", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{{Name: "a", Token: "t"}}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("want ErrInconclusive, got %v", err)
		}
	})

	t.Run("two sharing a token is one identity", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "same"}, {Name: "b", Token: "same"},
		}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("want ErrInconclusive, got %v", err)
		}
		// The reason has to name them, or an operator cannot tell which two.
		if !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), `"b"`) {
			t.Errorf("the reason should name both principals, got: %v", err)
		}
	})

	t.Run("anonymous principal is not an authenticated identity", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "anonymous"}, {Name: "owner", Token: "owner-token"},
		}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("want ErrInconclusive, got %v", err)
		}
	})

	t.Run("header-only identities run", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Headers: map[string]string{"X-API-Key": "key-a"}},
			{Name: "b", Headers: map[string]string{"X-API-Key": "key-b"}},
		}})
		if err != nil {
			t.Fatalf("distinct header credentials must be accepted: %v", err)
		}
	})

	t.Run("same token with distinct routing headers is unverified", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "shared", Headers: map[string]string{"X-Tenant-Id": "a"}},
			{Name: "b", Token: "shared", Headers: map[string]string{"X-Tenant-Id": "b"}},
		}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("a shared bearer token cannot prove distinct identities, got %v", err)
		}
	})

	t.Run("authorization override determines identity", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "token-a", Headers: map[string]string{"Authorization": "Bearer shared"}},
			{Name: "b", Token: "token-b", Headers: map[string]string{"authorization": "Bearer shared"}},
		}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("identical effective credentials must be inconclusive, got %v", err)
		}
	})

	t.Run("authorization scheme casing does not create another identity", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "shared"},
			{Name: "b", Headers: map[string]string{"Authorization": "bEaReR  shared"}},
		}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("equivalent authorization schemes must be inconclusive, got %v", err)
		}
	})

	t.Run("distinct authorization overrides run", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "shared", Headers: map[string]string{"Authorization": "Bearer token-a"}},
			{Name: "b", Token: "shared", Headers: map[string]string{"Authorization": "Bearer token-b"}},
		}})
		if err != nil {
			t.Fatalf("distinct effective credentials must be accepted: %v", err)
		}
	})

	t.Run("empty authorization override removes the token", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "token-a", Headers: map[string]string{"Authorization": ""}},
			{Name: "b", Token: "token-b"},
		}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("an empty effective credential must be inconclusive, got %v", err)
		}
	})

	t.Run("header names compare case-insensitively", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Headers: map[string]string{"X-API-Key": "shared"}},
			{Name: "b", Headers: map[string]string{"x-api-key": "shared"}},
		}})
		if !errors.Is(err, attack.ErrInconclusive) {
			t.Fatalf("identical wire headers must be inconclusive, got %v", err)
		}
	})

	t.Run("two distinct identities run", func(t *testing.T) {
		a, b, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "tok-a"}, {Name: "b", Token: "tok-b"},
		}})
		if err != nil {
			t.Fatalf("two distinct principals must be accepted: %v", err)
		}
		if a.Name != "a" || b.Name != "b" {
			t.Errorf("returned the wrong pair: %q and %q", a.Name, b.Name)
		}
	})

	t.Run("a third principal is ignored, not an error", func(t *testing.T) {
		_, _, err := twoPrincipals(attack.Options{Principals: []attack.Principal{
			{Name: "a", Token: "1"}, {Name: "b", Token: "2"}, {Name: "c", Token: "3"},
		}})
		if err != nil {
			t.Errorf("extra principals are ignored by these rules, not rejected: %v", err)
		}
	})
}

func TestPrincipalCredentialPresent(t *testing.T) {
	const target = "https://agent.example/a2a"
	vars := attack.NewVars(target, "")
	bare := attack.NewHTTPClient(attack.Options{}, vars)
	withToken := attack.NewHTTPClient(attack.Options{Token: "owner-token"}, vars)
	tests := []struct {
		name    string
		client  *attack.HTTPClient
		url     string
		headers map[string]string
		want    bool
	}{
		{"anonymous", bare, target, nil, false},
		{"bearer token", withToken, target, nil, true},
		{"header-only credential", bare, target, map[string]string{"X-API-Key": "key-a"}, true},
		{"empty override", withToken, target, map[string]string{"authorization": ""}, false},
		{"empty override with another credential", withToken, target,
			map[string]string{"authorization": "", "X-API-Key": "key-a"}, true},
		{"off-origin token", withToken, "https://other.example/a2a", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := principalCredentialPresent(tt.client, tt.url, tt.headers); got != tt.want {
				t.Errorf("principalCredentialPresent() = %t, want %t", got, tt.want)
			}
		})
	}
}
