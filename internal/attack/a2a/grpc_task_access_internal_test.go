package a2a

import "testing"

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
