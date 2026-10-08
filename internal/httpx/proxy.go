// Package httpx shares HTTP transport settings across scanning and authentication.
package httpx

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ProxyFunc uses the explicit proxy or, when empty, the environment.
// Invalid explicit values fail instead of silently sending traffic directly.
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

// normalizeProxyURL accepts bare host:port values as HTTP proxies.
func normalizeProxyURL(raw string) (*url.URL, error) {
	candidate := raw
	if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}
	u, err := url.Parse(candidate)
	if err != nil {
		return nil, errors.New("invalid proxy: malformed URL")
	}
	if u.Host == "" {
		return nil, errors.New("invalid proxy: missing host")
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, errors.New("invalid proxy: unsupported scheme")
	}
	return u, nil
}
