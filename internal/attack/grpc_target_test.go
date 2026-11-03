package attack_test

import (
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestParseA2AGRPCTarget(t *testing.T) {
	for _, tc := range []struct {
		raw, address string
		secure       bool
	}{
		{"grpcs://agent.example:443", "agent.example:443", true},
		{"grpc://127.0.0.1:50051", "127.0.0.1:50051", false},
		{"grpc://[::1]:50051", "[::1]:50051", false},
		{"grpc://localhost:50051", "localhost:50051", false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := attack.ParseA2AGRPCTarget(tc.raw)
			if err != nil || got.Address != tc.address || got.Secure != tc.secure {
				t.Fatalf("target=%+v err=%v", got, err)
			}
		})
	}
	for _, raw := range []string{
		"", " agent.example:443", "agent.example:443", "http://agent.example:443",
		"grpcs://agent.example", "grpcs://agent.example:0", "grpcs://agent.example:65536",
		"grpcs://user:pass@agent.example:443", "grpcs://agent.example:443/path",
		"grpcs://agent.example:443?x=1", "grpcs://agent.example:443#fragment",
		"grpc://agent.example:443", "grpc://192.0.2.3:443",
	} {
		t.Run("reject-"+raw, func(t *testing.T) {
			if _, err := attack.ParseA2AGRPCTarget(raw); err == nil {
				t.Fatal("unsafe gRPC target accepted")
			}
		})
	}
}
