package cli

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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
	_, err = fetchOAuthToken(context.Background(), "https://"+listener.Addr().String()+"/token", "client", "secret", nil, "", timeout, "", false)
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

func TestFetchOAuthTokenUsesExplicitProxy(t *testing.T) {
	var targetConnections atomic.Int32
	target := httptest.NewUnstartedServer(http.NotFoundHandler())
	target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			targetConnections.Add(1)
		}
	}
	target.StartTLS()
	defer target.Close()

	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "blocked", http.StatusBadGateway)
	}))
	defer proxy.Close()

	_, err := fetchOAuthToken(context.Background(), target.URL+"/token", "client", "secret", nil, "", time.Second, proxy.URL, false)
	if err == nil {
		t.Fatal("expected proxy rejection")
	}
	if proxyHits.Load() == 0 {
		t.Fatal("proxy was not contacted")
	}
	if targetConnections.Load() != 0 {
		t.Fatalf("token endpoint received %d direct connections", targetConnections.Load())
	}
}

func TestFetchOAuthTokenUsesSkipTLS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token"}`))
	}))
	defer target.Close()

	token, err := fetchOAuthToken(context.Background(), target.URL+"/token", "client", "secret", nil, "", time.Second, "", true)
	if err != nil {
		t.Fatalf("fetching token: %v", err)
	}
	if token != "token" {
		t.Fatalf("token = %q, want token", token)
	}
}
