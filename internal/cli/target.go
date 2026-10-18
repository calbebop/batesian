package cli

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/calbebop/batesian/internal/rules"
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

func selectsMCP(selected []*rules.Rule) bool {
	for _, rule := range selected {
		if strings.EqualFold(rule.Attack.Protocol, "mcp") {
			return true
		}
	}
	return false
}

func resourceFromTarget(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "", fmt.Errorf("invalid OAuth target resource URI")
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return canonicalOAuthResource(u.String())
}

func canonicalOAuthResource(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) ||
		u.Opaque != "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", fmt.Errorf("--oauth-resource must be an absolute HTTP(S) URI without userinfo, query, or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	if u.Path == "/" {
		u.Path = ""
		u.RawPath = ""
	}
	return u.String(), nil
}
