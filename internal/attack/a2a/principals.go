package a2a

import (
	"fmt"
	"maps"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// twoPrincipals requires two distinct credential and routing contexts.
func twoPrincipals(opts attack.Options) (a, b attack.Principal, err error) {
	if len(opts.Principals) < 2 {
		return a, b, fmt.Errorf("%w: this rule compares two authenticated identities and %d "+
			"were configured; pass two --principal flags (or a config with two principals) to run it",
			attack.ErrInconclusive, len(opts.Principals))
	}
	a, b = opts.Principals[0], opts.Principals[1]
	aHeaders, bHeaders := principalHeaders(a), principalHeaders(b)
	if len(aHeaders) == 0 || len(bHeaders) == 0 {
		return a, b, fmt.Errorf("%w: principals %q and %q each need a bearer token or identity-routing headers",
			attack.ErrInconclusive, a.Name, b.Name)
	}
	sharedAuthorization := aHeaders["authorization"] != "" &&
		aHeaders["authorization"] == bHeaders["authorization"]
	if sharedAuthorization || maps.Equal(aHeaders, bHeaders) {
		return a, b, fmt.Errorf("%w: principals %q and %q do not establish distinct authorization contexts",
			attack.ErrInconclusive, a.Name, b.Name)
	}
	return a, b, nil
}

// principalHeaders normalizes a principal's effective credentials and routing headers.
func principalHeaders(p attack.Principal) map[string]string {
	headers := make(map[string]string, len(p.Headers)+1)
	if p.Token != "" {
		headers["authorization"] = "bearer " + p.Token
	}
	for name, value := range p.Headers {
		key := strings.ToLower(name)
		if key == "authorization" {
			value = canonicalAuthorization(value)
		}
		if value == "" {
			delete(headers, key)
		} else {
			headers[key] = value
		}
	}
	return headers
}

func canonicalAuthorization(value string) string {
	value = strings.TrimSpace(value)
	scheme, credential, ok := strings.Cut(value, " ")
	if !ok {
		return value
	}
	return strings.ToLower(scheme) + " " + strings.TrimLeft(credential, " ")
}
