package mcp

import (
	"strings"
	"testing"
)

func TestDefaultPortVariant(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://api.example.com?tenant=one", "https://api.example.com:443?tenant=one"},
		{"https://api.example.com/mcp?tenant=one", "https://api.example.com:443/mcp?tenant=one"},
		{"https://api.example.com:443/mcp", "https://api.example.com/mcp"},
		{"http://[::1]?tenant=one", "http://[::1]:80?tenant=one"},
		{"http://[::1]:80/mcp", "http://[::1]/mcp"},
		{"https://api.example.com:8443/mcp", ""},
		{"tenant:one", ""},
		{"tenant", ""},
	} {
		if got := defaultPortVariant(tc.input); got != tc.want {
			t.Errorf("defaultPortVariant(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestCaseCanonicalizationVariant(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://api.example.com?tenant=one", "Https://api.example.com?tenant=one"},
		{"https://API.example.com/mcp", "https://api.example.com/mcp"},
		{"https://api.example.com:8443/mcp", "Https://api.example.com:8443/mcp"},
		{"tenant", "Tenant"},
		{"123", ""},
	} {
		if got := caseCanonicalizationVariant(tc.input); got != tc.want {
			t.Errorf("caseCanonicalizationVariant(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestAudienceProbeDescriptionsOmitValues(t *testing.T) {
	const marker = "private-audience-marker"
	for _, probe := range buildProbes("https://api.example.com/mcp?tenant=" + marker) {
		if strings.Contains(probe.descSuffix, marker) {
			t.Errorf("%s description disclosed the audience", probe.name)
		}
	}
	if probes := buildProbes("123"); len(probes) != 3 {
		t.Fatalf("nonalphabetic audience has %d probes, want 3", len(probes))
	}
}
