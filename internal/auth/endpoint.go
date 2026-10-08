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
		return nil, fmt.Errorf("%s is invalid", label)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("%s must use HTTPS", label)
	}
	if parsed.Hostname() == "" {
		return nil, fmt.Errorf("%s must include a host", label)
	}
	if strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%s must not include a fragment", label)
	}
	if _, err := url.ParseQuery(parsed.RawQuery); err != nil {
		return nil, fmt.Errorf("%s has an invalid query", label)
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("%s has an invalid port", label)
		}
	}
	return parsed, nil
}
