// Package httpx holds HTTP transport wiring shared by the scan path, the recon
// clients and the OAuth flows. It exists so those three can agree on proxy
// behaviour without importing each other.
package httpx

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ProxyFunc returns the Proxy function for an http.Transport.
//
// raw is the operator's explicit choice (--proxy or the config file). When it is
// empty the environment is consulted, so HTTPS_PROXY, HTTP_PROXY and NO_PROXY work
// with no flag, matching what any Go program using http.DefaultTransport does.
//
// This is not a nicety. Every transport in this repository was constructed as a
// bare &http.Transport{}, which ignores the environment, while the OAuth clients
// left Transport nil and so picked up http.DefaultTransport. An operator who set
// HTTPS_PROXY captured the OAuth traffic and nothing else, and a capture that
// looks complete but is not is worse than no proxy support at all.
//
// An unparseable value is an error rather than a silent fallback to the
// environment: a mistyped proxy that quietly sends traffic direct is exactly the
// failure this is meant to remove.
func ProxyFunc(raw string) (func(*http.Request) (*url.URL, error), error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return http.ProxyFromEnvironment, nil
	}
	u, err := normalizeProxyURL(raw)
	if err != nil {
		return nil, err
	}
	return http.ProxyURL(u), nil
}

// normalizeProxyURL accepts the forms an operator actually types. A bare
// host:port is the common one (Burp and ZAP both present themselves that way),
// and url.Parse reads it as a path rather than a host, so the scheme is supplied.
func normalizeProxyURL(raw string) (*url.URL, error) {
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid proxy %q: no host", raw)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("invalid proxy %q: unsupported scheme %q", raw, u.Scheme)
	}
	return u, nil
}
