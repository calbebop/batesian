package auth

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestTokenEndpointClientUsesTimeout(t *testing.T) {
	const timeout = 125 * time.Millisecond

	client, err := tokenEndpointClient(nil, timeout, "", false)
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	if client.Timeout != timeout {
		t.Fatalf("timeout = %s, want %s", client.Timeout, timeout)
	}

	base := &http.Client{Timeout: time.Second}
	clone, err := tokenEndpointClient(base, timeout, "", false)
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

func TestTokenEndpointClientSkipTLSClonesTransport(t *testing.T) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{}}
	base := &http.Client{Transport: transport}

	client, err := tokenEndpointClient(base, time.Second, "", true)
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	clone := client.Transport.(*http.Transport)
	if !clone.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS verification remains enabled")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("base transport was modified")
	}

	client, err = tokenEndpointClient(&http.Client{}, time.Second, "", true)
	if err != nil {
		t.Fatalf("creating client with default transport: %v", err)
	}
	clone = client.Transport.(*http.Transport)
	if !clone.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS verification remains enabled on the default transport")
	}
}
