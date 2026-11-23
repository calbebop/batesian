package a2a

import (
	"reflect"
	"testing"
)

func TestPeerMetadataURLs(t *testing.T) {
	const origin = "https://agent.example.test"
	for _, tc := range []struct {
		name, base, endpoint string
		want                 []peerMetadataCandidate
	}{
		{
			name: "trailing slash", base: origin, endpoint: origin + "/tenant/a2a/",
			want: []peerMetadataCandidate{
				{url: origin + "/.well-known/oauth-protected-resource/tenant/a2a/", resource: origin + "/tenant/a2a/", appliesToTarget: true},
				{url: origin + "/.well-known/oauth-protected-resource", resource: origin, appliesToTarget: true},
			},
		},
		{
			name: "query and path target", base: origin + "/tenant", endpoint: origin + "/tenant/a2a?tenant=one",
			want: []peerMetadataCandidate{
				{url: origin + "/.well-known/oauth-protected-resource/tenant/a2a?tenant=one", resource: origin + "/tenant/a2a?tenant=one", appliesToTarget: true},
				{url: origin + "/.well-known/oauth-protected-resource/tenant", resource: origin + "/tenant", appliesToTarget: true},
				{url: origin + "/.well-known/oauth-protected-resource", resource: origin, appliesToTarget: false},
			},
		},
		{
			name: "off-origin route", base: origin, endpoint: "https://other.example.test/a2a",
			want: []peerMetadataCandidate{
				{url: origin + "/.well-known/oauth-protected-resource", resource: origin, appliesToTarget: true},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerMetadataURLs(tc.base, tc.endpoint); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("peerMetadataURLs() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
