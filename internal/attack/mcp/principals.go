package mcp

import (
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

func configuredTaskPrincipal(p attack.Principal) (taskPrincipal, error) {
	headers := make(map[string]string, len(p.Headers))
	for name, value := range p.Headers {
		key := http.CanonicalHeaderKey(name)
		if previous, exists := headers[key]; exists && previous != value {
			return taskPrincipal{}, fmt.Errorf("%w: principal %q has conflicting values for %s",
				attack.ErrInconclusive, p.Name, key)
		}
		headers[key] = value
	}
	return taskPrincipal{name: p.Name, token: p.Token, headers: headers}, nil
}

func attachPrincipal(h map[string]string, p taskPrincipal) {
	if p.token != "" {
		h["Authorization"] = "Bearer " + p.token
	}
	for key, value := range p.headers {
		h[key] = value
	}
}

func principalIdentityHeaders(p taskPrincipal) map[string]string {
	headers := map[string]string{}
	attachPrincipal(headers, p)
	for key, value := range headers {
		value = strings.TrimSpace(value)
		if value == "" {
			delete(headers, key)
			continue
		}
		if key == "Authorization" {
			scheme, credential, ok := strings.Cut(value, " ")
			if ok {
				value = strings.ToLower(scheme) + " " + strings.TrimLeft(credential, " ")
			}
		}
		headers[key] = value
	}
	return headers
}

func samePrincipalIdentity(a, b taskPrincipal) bool {
	return maps.Equal(principalIdentityHeaders(a), principalIdentityHeaders(b))
}
