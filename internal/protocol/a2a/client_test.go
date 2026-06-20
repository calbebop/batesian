package a2a

import (
	"net/http"
	"testing"
)

// TestWithSkipTLSVerify_TakesEffect confirms the security-relevant skip-TLS
// option actually enables InsecureSkipVerify on a normally-constructed client.
func TestWithSkipTLSVerify_TakesEffect(t *testing.T) {
	c, err := NewClient("https://example.com", WithSkipTLSVerify())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("WithSkipTLSVerify did not enable InsecureSkipVerify")
	}
}

// TestWithSkipTLSVerify_NilConfig exercises a transport with no TLS config. The
// option must create one and enable InsecureSkipVerify; before the fix this
// silently no-oped, leaving skip-TLS unapplied.
func TestWithSkipTLSVerify_NilConfig(t *testing.T) {
	c := &Client{http: &http.Client{Transport: &http.Transport{}}} // nil TLSClientConfig
	WithSkipTLSVerify()(c)
	tr := c.http.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("WithSkipTLSVerify should create a TLS config and enable InsecureSkipVerify")
	}
}
