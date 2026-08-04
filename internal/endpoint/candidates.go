// Package endpoint builds the list of URLs to probe when locating a JSON-RPC
// handler under a target.
//
// The A2A and MCP rule sets and the probe command each need this, with their
// own conventional paths, and they need to agree on how a target that already
// names a path is treated. Keeping the rule in one place is deliberate: three
// copies of the same question have drifted apart in this repository before.
package endpoint

import (
	"net/url"
	"strings"
)

// Candidates returns the URLs to try under baseURL, in probe order.
//
// Each entry in paths is appended to the target, which is how a bare origin is
// searched: https://host yields https://host/mcp, https://host/ and so on.
//
// A target that already names a path is a different case. An operator scanning
// an MCP server almost always has its published URL to hand, and that URL
// usually carries the path the handler is mounted at (https://host/mcp is the
// convention). Appending to that reaches https://host/mcp/mcp and friends but
// never https://host/mcp itself, so nothing answers and every rule reports that
// it could not find a testable endpoint. The target the operator actually named
// is therefore probed first, ahead of the conventional paths.
//
// Only the appended forms are tried for a bare origin, exactly as before: with
// no path to preserve there is nothing to put first, so probe order for the
// common case is unchanged.
//
// One trailing slash is trimmed from baseURL first, so https://host/mcp/ is
// treated as https://host/mcp rather than producing https://host/mcp//mcp.
func Candidates(baseURL string, paths []string) []string {
	base := strings.TrimSuffix(baseURL, "/")

	out := make([]string, 0, len(paths)+1)
	if hasPath(base) {
		out = append(out, base)
	}
	for _, p := range paths {
		out = append(out, base+p)
	}
	return dedupe(out)
}

// hasPath reports whether the URL names a path beyond the root. A URL that will
// not parse is treated as having none, which keeps the caller on the historical
// append-only behaviour rather than failing.
func hasPath(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.Trim(u.Path, "/") != ""
}

// dedupe removes repeated entries while preserving order, so a path target
// whose conventional suffix matches its own path is not probed twice.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
