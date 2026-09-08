package cli

import (
	"fmt"
	"net/url"
)

func validateTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid target URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target URL must use http or https scheme, got %q", u.Scheme)
	}
	if u.Opaque != "" {
		return fmt.Errorf("invalid target URL %q: opaque URLs are not supported", raw)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("invalid target URL %q: missing host", raw)
	}
	return nil
}
