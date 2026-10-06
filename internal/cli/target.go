package cli

import (
	"errors"
	"net/url"
)

func validateTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid target URL syntax")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("invalid target URL: must use http or https scheme")
	}
	if u.Opaque != "" {
		return errors.New("invalid target URL: opaque URLs are not supported")
	}
	if u.Hostname() == "" {
		return errors.New("invalid target URL: missing host")
	}
	return nil
}
