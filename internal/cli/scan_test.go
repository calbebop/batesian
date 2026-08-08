package cli

import (
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/config"
)

func TestParsePrincipalFlag_Valid(t *testing.T) {
	p, err := parsePrincipalFlag("name=tenant-a,token=eyJabc,tenant=A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "tenant-a" || p.Token != "eyJabc" || p.Tenant != "A" {
		t.Errorf("parsed principal mismatch: %+v", p)
	}
}

func TestParsePrincipalFlag_MissingName(t *testing.T) {
	if _, err := parsePrincipalFlag("token=abc,tenant=A"); err == nil {
		t.Error("expected error when name= is absent, got nil")
	}
}

func TestParsePrincipalFlag_UnknownKey(t *testing.T) {
	if _, err := parsePrincipalFlag("name=a,role=admin"); err == nil {
		t.Error("expected error for unknown key, got nil")
	}
}

func TestParsePrincipalFlag_InvalidSegment(t *testing.T) {
	if _, err := parsePrincipalFlag("name=a,justakey"); err == nil {
		t.Error("expected error for key without =, got nil")
	}
}

// Five multi-principal A2A rules send Principal.Headers. Multi-tenant deployments
// commonly resolve the tenant at a gateway and pass it downstream in a header, so a
// flag that cannot express one cannot describe the identities it is comparing.
// Against a header-scoped agent that isolates correctly, the headerless form
// produced two false-positive cross-tenant findings.
func TestParsePrincipalFlag_HeadersAreRepeatable(t *testing.T) {
	p, err := parsePrincipalFlag("name=a,token=t,tenant=A,header=X-Tenant-Id:A,header=X-Env:prod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Headers) != 2 {
		t.Fatalf("expected both headers, got %+v", p.Headers)
	}
	if p.Headers["X-Tenant-Id"] != "A" || p.Headers["X-Env"] != "prod" {
		t.Errorf("header values mismatch: %+v", p.Headers)
	}
	// The other fields must still parse alongside.
	if p.Name != "a" || p.Token != "t" || p.Tenant != "A" {
		t.Errorf("non-header fields mismatch: %+v", p)
	}
}

// A header value may itself contain colons, e.g. a URL, so only the first splits.
func TestParsePrincipalFlag_HeaderValueKeepsLaterColons(t *testing.T) {
	p, err := parsePrincipalFlag("name=a,header=X-Origin:https://tenant-a.example.test:8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := p.Headers["X-Origin"]; got != "https://tenant-a.example.test:8443" {
		t.Errorf("value should keep everything after the first colon, got %q", got)
	}
}

func TestParsePrincipalFlag_HeaderNeedsNameAndValue(t *testing.T) {
	for _, bad := range []string{"name=a,header=NoColon", "name=a,header=:justvalue"} {
		if _, err := parsePrincipalFlag(bad); err == nil {
			t.Errorf("expected an error for %q, got nil", bad)
		}
	}
}

// The config file spells this as a `headers:` map, so it is the first thing an
// operator reaches for here. The error has to point at the form that works.
func TestParsePrincipalFlag_PluralHeadersIsGuided(t *testing.T) {
	_, err := parsePrincipalFlag("name=a,headers=X-Tenant-Id:A")
	if err == nil {
		t.Fatal("expected an error for headers=, got nil")
	}
	if !strings.Contains(err.Error(), "header=Name:Value") {
		t.Errorf("error should name the working form, got: %v", err)
	}
}

func TestBuildPrincipals_MergesConfigThenFlags(t *testing.T) {
	cfgPrincipals := []config.PrincipalConfig{
		{Name: "tenant-a", Token: "token-a", Tenant: "A"},
	}
	flags := []string{"name=tenant-b,token=token-b,tenant=B"}

	got, err := buildPrincipals(cfgPrincipals, flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 principals, got %d", len(got))
	}
	if got[0].Name != "tenant-a" || got[1].Name != "tenant-b" {
		t.Errorf("merge order wrong (config first, flags appended): %+v", got)
	}
}

func TestBuildPrincipals_DuplicateAcrossSources(t *testing.T) {
	cfgPrincipals := []config.PrincipalConfig{{Name: "dup", Token: "x"}}
	flags := []string{"name=dup,token=y"}
	if _, err := buildPrincipals(cfgPrincipals, flags); err == nil {
		t.Error("expected duplicate-name error across config + flags, got nil")
	}
}

func TestBuildPrincipals_Empty(t *testing.T) {
	got, err := buildPrincipals(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no principals, got %d", len(got))
	}
}

func TestEffectiveTimeout(t *testing.T) {
	tests := []struct {
		name        string
		flagChanged bool
		flagVal     int
		cfgVal      int
		want        int
	}{
		// The bug this guards: an explicit --timeout 10 (equal to the default)
		// must not be overridden by a config value.
		{"explicit flag equal to default wins over config", true, 10, 30, 10},
		{"explicit flag wins even when config is zero", true, 25, 0, 25},
		{"config used when flag not set", false, 10, 30, 30},
		{"flag default when neither set", false, 10, 0, 10},
		{"non-positive config ignored", false, 10, -5, 10},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveTimeout(tc.flagChanged, tc.flagVal, tc.cfgVal); got != tc.want {
				t.Errorf("effectiveTimeout(%v, %d, %d) = %d, want %d", tc.flagChanged, tc.flagVal, tc.cfgVal, got, tc.want)
			}
		})
	}
}

func TestEffectiveSkipTLS(t *testing.T) {
	tests := []struct {
		name        string
		flagChanged bool
		flagVal     bool
		cfgVal      bool
		want        bool
	}{
		// The bug this guards: an explicit --skip-tls=false must override a config
		// that sets skipTLS: true.
		{"explicit false overrides config true", true, false, true, false},
		{"explicit true used", true, true, false, true},
		{"config used when flag not set", false, false, true, true},
		{"both unset", false, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveSkipTLS(tc.flagChanged, tc.flagVal, tc.cfgVal); got != tc.want {
				t.Errorf("effectiveSkipTLS(%v, %v, %v) = %v, want %v", tc.flagChanged, tc.flagVal, tc.cfgVal, got, tc.want)
			}
		})
	}
}
