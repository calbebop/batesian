package mcp

import "testing"

func TestProtectedResourceMetadataBinding(t *testing.T) {
	const origin = "https://resource.example.test"
	const wellKnown = origin + "/.well-known/oauth-protected-resource"
	for _, tc := range []struct {
		name, target, resource, metadata, challenged string
		want                                         bool
	}{
		{"root", origin, origin, wellKnown, "", true},
		{"wrong root resource", origin, origin + "/mcp", wellKnown, "", false},
		{"path", origin + "/mcp", origin + "/mcp", wellKnown + "/mcp", "", true},
		{"case difference", origin, "https://RESOURCE.example.test", wellKnown, "", false},
		{"query", origin + "/mcp?tenant=one", origin + "/mcp?tenant=one", wellKnown + "/mcp?tenant=one", "", true},
		{"wrong query", origin + "/mcp?tenant=one", origin + "/mcp?tenant=two", wellKnown + "/mcp?tenant=one", "", false},
		{"challenge", origin, origin + "/mcp", origin + "/metadata", origin + "/mcp", true},
		{"wrong challenge resource", origin, origin, origin + "/metadata", origin + "/mcp", false},
		{"invalid well-known suffix", origin, origin, wellKnown + "-other", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := prmMatchesTarget(tc.target, tc.resource, tc.metadata, tc.challenged); got != tc.want {
				t.Fatalf("prmMatchesTarget() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOAuthWellKnownURLsRetainResourceQuery(t *testing.T) {
	for _, tc := range []struct{ target, want string }{
		{"https://resource.example.test/mcp?tenant=one", "https://resource.example.test/.well-known/oauth-protected-resource/mcp?tenant=one"},
		{"https://resource.example.test/mcp/?tenant=one", "https://resource.example.test/.well-known/oauth-protected-resource/mcp/?tenant=one"},
	} {
		urls := oauthWellKnownURLs(tc.target, "/.well-known/oauth-protected-resource")
		if len(urls) == 0 || urls[0] != tc.want {
			t.Errorf("first metadata URL for %q = %q, want %q", tc.target, urls, tc.want)
		}
	}
}
