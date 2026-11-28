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
	Variants      []string
}

type MCPFetchRobotsRedirectProbe struct {
	Origin        string
	PrivatePath   string
	PrivateMarker string
	RedirectPath  string
}

func ValidMCPFetchRobotsRedirectProbe(p *MCPFetchRobotsRedirectProbe) bool {
	return p != nil &&
		ValidMCPFetchRobotsProbe(&MCPFetchRobotsProbe{
			Origin: p.Origin, PrivatePath: p.PrivatePath, PrivateMarker: p.PrivateMarker,
		}) &&
		fetchCanaryPath.MatchString(p.RedirectPath) &&
		!strings.HasPrefix(p.RedirectPath, p.PrivatePath)
}

type MCPFetchRobotsAlternate struct {
	Variant string
	Path    string
}

func FetchRobotsAlternates(p *MCPFetchRobotsProbe) []MCPFetchRobotsAlternate {
	variants := p.Variants
	if len(variants) == 0 {
		variants = []string{"double_slash"}
	}
	name := strings.TrimPrefix(p.PrivatePath, "/")
	paths := map[string]string{
		"double_slash":      "/" + p.PrivatePath,
		"backslash":         "/batesian-probe\\..\\" + name,
		"encoded_backslash": "/batesian-probe%5c..%5c" + name,
		"path_parameter":    "/batesian-probe/..;/" + name,
	}
	result := make([]MCPFetchRobotsAlternate, 0, len(variants))
	for _, variant := range variants {
		result = append(result, MCPFetchRobotsAlternate{Variant: variant, Path: paths[variant]})
	}
	return result
}

var fetchCanaryPath = regexp.MustCompile(`^/batesian-[A-Za-z0-9_-]{4,80}$`)
var fetchCanaryMarker = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func ValidMCPFetchRobotsProbe(p *MCPFetchRobotsProbe) bool {
	if p == nil || !fetchCanaryPath.MatchString(p.PrivatePath) ||
		!fetchCanaryMarker.MatchString(p.PrivateMarker) {
		return false
	}
	if len(p.Variants) > 4 {
		return false
	}
	seen := map[string]bool{}
	for _, variant := range p.Variants {
		switch variant {
		case "double_slash", "backslash", "encoded_backslash", "path_parameter":
		default:
			return false
		}
		if seen[variant] {
			return false
		}
		seen[variant] = true
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
