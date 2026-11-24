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
	const target = "https://resource.example.test/mcp?tenant=one"
	urls := oauthWellKnownURLs(target, "/.well-known/oauth-protected-resource")
	const want = "https://resource.example.test/.well-known/oauth-protected-resource/mcp?tenant=one"
	if len(urls) == 0 || urls[0] != want {
		t.Fatalf("first metadata URL = %q, want %q", urls, want)
	}
}
