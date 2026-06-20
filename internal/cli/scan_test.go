package cli

import (
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
