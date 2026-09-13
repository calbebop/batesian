package cli

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestFetchOAuthTokenUsesRequestTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	release := make(chan struct{})
	accepted := make(chan struct{}, 1)
	t.Cleanup(func() {
		close(release)
		_ = listener.Close()
	})

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		accepted <- struct{}{}
		select {
		case <-release:
		case <-time.After(time.Second):
		}
	}()

	const timeout = 250 * time.Millisecond
	start := time.Now()
	_, err = fetchOAuthToken(context.Background(), "https://"+listener.Addr().String()+"/token", "client", "secret", nil, "", timeout)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected stalled token request to fail")
	}
	if elapsed >= 750*time.Millisecond {
		t.Fatalf("token request took %s, want configured timeout %s", elapsed, timeout)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("token endpoint was not contacted")
	}
}
