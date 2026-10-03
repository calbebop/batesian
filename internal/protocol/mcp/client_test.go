package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
// nil-dereferenced.
func TestWithSkipTLSVerify_NilConfig(t *testing.T) {
	c := &Client{http: &http.Client{Transport: &http.Transport{}}} // nil TLSClientConfig
	WithSkipTLSVerify()(c)
	tr := c.http.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("WithSkipTLSVerify should create a TLS config and enable InsecureSkipVerify")
	}
}

func TestTryDiscover_RejectsUnrelatedOrIncompleteReplies(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		version string
		kind    string
	}{
		{name: "wrong id", id: "unrelated", version: modernVersion, kind: "complete"},
		{name: "wrong version", id: "batesian-probe-discover", version: "2025-11-25", kind: "complete"},
		{name: "incomplete", id: "batesian-probe-discover", version: modernVersion, kind: "input_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0", "id": tc.id,
					"result": map[string]interface{}{
						"resultType": tc.kind, "supportedVersions": []string{tc.version},
						"capabilities": map[string]interface{}{"tools": map[string]interface{}{}},
					},
				})
			}))
			defer srv.Close()
			client, err := NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.tryDiscover(context.Background(), srv.URL); err == nil {
				t.Fatal("untrusted discovery reply was accepted")
			}
		})
	}
}

func TestListResult_RejectsModernProtocolErrors(t *testing.T) {
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":10,"error":{"code":-32601,"message":"not found"}}`,
		`{"jsonrpc":"2.0","id":11,"result":{"resultType":"complete","resources":[]}}`,
		`{"jsonrpc":"2.0","id":10,"result":{"resultType":"input_required","tools":[]}}`,
	} {
		if _, err := listResult([]byte(body), 10, true); err == nil {
			t.Fatalf("invalid modern list result was accepted: %s", body)
		}
	}
}
