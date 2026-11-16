package a2a

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestGRPCCardDiscoveryIgnoresConfiguredVersion(t *testing.T) {
	var versions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cardPathPrimary {
			http.NotFound(w, r)
			return
		}
		versions = append(versions, r.Header.Get("A2A-Version"))
		if r.Header.Get("A2A-Version") == "1.0" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("A2A-Version") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"supportedInterfaces":[{"url":"http://example.invalid:50051","protocolBinding":"GRPC","protocolVersion":"1.0"}]}`))
	}))
	defer server.Close()
	client := attack.NewHTTPClient(attack.Options{TimeoutSeconds: 5}, attack.NewVars(server.URL, ""))
	_, ok := grpcDiscoveryCard(t.Context(), client, server.URL, map[string]string{"a2a-version": "9.9"})
	if !ok || !reflect.DeepEqual(versions, []string{"1.0", ""}) {
		t.Fatalf("card discovery: ok=%v versions=%v", ok, versions)
	}
}

func TestGRPCCardAddress(t *testing.T) {
	for _, tc := range []struct{ raw, address, scheme string }{
		{"grpc.example:50051", "", ""},
		{"http://grpc.example:50051", "grpc.example:50051", "http"},
		{"https://grpc.example", "grpc.example:443", "https"},
		{"https://grpc.example:50051/", "grpc.example:50051", "https"},
		{"grpcs://[::1]:50051", "[::1]:50051", "grpcs"},
		{"https://grpc.example/a2a", "", ""},
		{"ftp://grpc.example:50051", "", ""},
		{"https://user:pass@grpc.example", "", ""},
		{"https://grpc.example?token=secret", "", ""},
		{"https://grpc.example:0", "", ""},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			address, scheme := grpcCardAddress(tc.raw)
			if address != tc.address || scheme != tc.scheme {
				t.Fatalf("address=%q scheme=%q, want %q %q", address, scheme, tc.address, tc.scheme)
			}
		})
	}
}
