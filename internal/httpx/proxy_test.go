package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The forms an operator actually types. A bare host:port is the common one, since
// Burp and ZAP both present themselves that way, and url.Parse reads it as a path
// rather than a host unless a scheme is supplied.
func TestProxyFunc_AcceptedForms(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"bare host and port", "127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"explicit http", "http://127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"https proxy", "https://proxy.internal:3128", "https://proxy.internal:3128"},
		{"socks5", "socks5://127.0.0.1:1080", "socks5://127.0.0.1:1080"},
		{"hostname without port", "proxy.internal", "http://proxy.internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := ProxyFunc(tt.raw)
			if err != nil {
				t.Fatalf("ProxyFunc(%q): %v", tt.raw, err)
			}
			req := httptest.NewRequest(http.MethodGet, "https://target.example/mcp", nil)
			got, err := fn(req)
			if err != nil {
				t.Fatalf("resolving proxy: %v", err)
			}
			if got == nil {
				t.Fatal("expected a proxy URL, got nil (traffic would go direct)")
			}
			if got.String() != tt.want {
				t.Errorf("proxy = %q, want %q", got, tt.want)
			}
		})
	}
}

// An unusable value must be an error, not a silent fallback. A mistyped proxy that
// quietly sends traffic direct is the failure this option exists to prevent: the
// operator would believe they were intercepting when they were not.
func TestProxyFunc_RejectsUnusableValues(t *testing.T) {
	for _, raw := range []string{"://nope", "ftp://proxy:21", "http://"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ProxyFunc(raw); err == nil {
				t.Errorf("ProxyFunc(%q) should fail rather than fall back to a direct connection", raw)
			}
		})
	}
}

// An empty value hands control to the environment, which is what makes
// HTTPS_PROXY work with no flag and NO_PROXY carve-outs keep working.
func TestProxyFunc_EmptyUsesEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
	t.Setenv("NO_PROXY", "excluded.example")

	fn, err := ProxyFunc("")
	if err != nil {
		t.Fatalf("ProxyFunc(\"\"): %v", err)
	}

	proxied := httptest.NewRequest(http.MethodGet, "https://target.example/mcp", nil)
	got, err := fn(proxied)
	if err != nil {
		t.Fatalf("resolving proxy: %v", err)
	}
	if got == nil || got.String() != "http://127.0.0.1:9999" {
		t.Errorf("HTTPS_PROXY should apply when no proxy is configured, got %v", got)
	}

	excluded := httptest.NewRequest(http.MethodGet, "https://excluded.example/mcp", nil)
	got, err = fn(excluded)
	if err != nil {
		t.Fatalf("resolving proxy: %v", err)
	}
	if got != nil {
		t.Errorf("NO_PROXY host should bypass the proxy, got %v", got)
	}
}

// An explicit value must beat the environment, so --proxy is authoritative when
// the operator sets both.
func TestProxyFunc_ExplicitBeatsEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1111")

	fn, err := ProxyFunc("127.0.0.1:2222")
	if err != nil {
		t.Fatalf("ProxyFunc: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://target.example/mcp", nil)
	got, err := fn(req)
	if err != nil {
		t.Fatalf("resolving proxy: %v", err)
	}
	if got == nil || got.String() != "http://127.0.0.1:2222" {
		t.Errorf("explicit proxy should win over HTTPS_PROXY, got %v", got)
	}
}
