package auth

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func parseOAuthEndpoint(raw, label string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is invalid: %w", label, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("%s must use HTTPS (got: %s)", label, raw)
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("%s must include a host (got: %s)", label, raw)
	}
	if strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%s must not include a fragment (got: %s)", label, raw)
	}
	if _, err := url.ParseQuery(parsed.RawQuery); err != nil {
		return nil, fmt.Errorf("%s has an invalid query: %w", label, err)
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("%s has an invalid port %q", label, port)
		}
	}
	return parsed, nil
}
