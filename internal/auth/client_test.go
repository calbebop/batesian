package auth

import (
	"net/http"
	"testing"
	"time"
)

func TestTokenEndpointClientUsesTimeout(t *testing.T) {
	const timeout = 125 * time.Millisecond

	client, err := tokenEndpointClient(nil, timeout, "")
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	if client.Timeout != timeout {
		t.Fatalf("timeout = %s, want %s", client.Timeout, timeout)
	}

	base := &http.Client{Timeout: time.Second}
	clone, err := tokenEndpointClient(base, timeout, "")
	if err != nil {
		t.Fatalf("cloning client: %v", err)
	}
	if clone.Timeout != timeout {
		t.Fatalf("clone timeout = %s, want %s", clone.Timeout, timeout)
	}
	if base.Timeout != time.Second {
		t.Fatalf("base timeout changed to %s", base.Timeout)
	}
}
