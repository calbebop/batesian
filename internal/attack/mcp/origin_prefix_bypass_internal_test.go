package mcp

import (
	"net/url"
	"testing"
)

func TestPrefixProbesBrowserOriginShape(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"http://127.0.0.1:7811/mcp", "http://127.0.0.1." + prefixCanaryZone + ":7811"},
		{"http://Service.Example:80/mcp", "http://service.example." + prefixCanaryZone},
		{"https://Service.Example:8443/mcp", "https://service.example." + prefixCanaryZone + ":8443"},
		{"http://[::1]:7811/mcp", ""},
		{"http://service.example:080/mcp", "http://service.example." + prefixCanaryZone},
		{"http://service.example:00081/mcp", "http://service.example." + prefixCanaryZone + ":81"},
		{"http://service.example:65536/mcp", ""},
		{"https://exämple.test/mcp", ""},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			target, err := url.Parse(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			probes := prefixProbes(target)
			if tc.want == "" {
				if len(probes) != 0 {
					t.Fatalf("expected no browser-shaped probe, got %+v", probes)
				}
				return
			}
			if len(probes) != 1 || probes[0].origin != tc.want {
				t.Fatalf("got %+v, want %q", probes, tc.want)
			}
			parsed, err := url.Parse(probes[0].origin)
			if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
				parsed.Hostname() != probes[0].attackerHost {
				t.Fatalf("probe is not a bare foreign Origin: %+v err=%v", parsed, err)
			}
		})
	}
}
