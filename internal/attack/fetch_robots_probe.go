package attack

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// MCPFetchRobotsProbe names an operator-controlled robots canary origin.
type MCPFetchRobotsProbe struct {
	Origin        string
	PrivatePath   string
	PrivateMarker string
}

var fetchCanaryPath = regexp.MustCompile(`^/batesian-[A-Za-z0-9_-]{4,80}$`)
var fetchCanaryMarker = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func ValidMCPFetchRobotsProbe(p *MCPFetchRobotsProbe) bool {
	if p == nil || !fetchCanaryPath.MatchString(p.PrivatePath) ||
		!fetchCanaryMarker.MatchString(p.PrivateMarker) {
		return false
	}
	u, err := url.Parse(p.Origin)
	if err != nil {
		return false
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if !strings.EqualFold(u.Hostname(), "localhost") && (ip == nil || !ip.IsLoopback()) {
			return false
		}
	}
	return (u.Scheme == "https" || u.Scheme == "http") &&
		u.Hostname() != "" && u.User == nil && u.Opaque == "" &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == "" &&
		strings.TrimSpace(p.Origin) == p.Origin && u.String() == p.Origin
}
