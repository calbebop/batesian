// Package oob provides a local out-of-band HTTP listener for detecting SSRF callbacks.
//
// When testing push-notification SSRF, Batesian registers a callback URL pointing
// at this listener and waits for the target A2A server to call back. If the
// server makes an outbound request to the registered URL, the SSRF is confirmed.
//
// Limitations: the local listener only works when the target A2A server can reach
// the Batesian host (e.g., same network, or target is on the public internet with a
// routable IP). For testing targets that cannot reach the scanning host, use an
// external OOB server (--oob-url flag) instead.
package oob

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Callback holds the data captured from an incoming OOB callback request.
type Callback struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

// Listener is a local HTTP server that captures incoming requests.
type Listener struct {
	server    *http.Server
	addr      string
	callbacks chan Callback
	mu        sync.Mutex
	started   bool
}

// New creates a Listener that will bind to a random available port on all interfaces.
func New() *Listener {
	l := &Listener{
		callbacks: make(chan Callback, 64),
	}
	return l
}

// Start binds the listener to a port and begins serving.
// Returns the base URL to register as the callback (e.g. "http://10.0.0.5:54321").
func (l *Listener) Start() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started {
		return l.URL(), nil
	}

	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return "", fmt.Errorf("oob listener: binding port: %w", err)
	}
	l.addr = ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handleCallback)

	l.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		_ = l.server.Serve(ln)
	}()

	l.started = true
	return l.URL(), nil
}

// URL returns the base URL of the listener.
// The outbound IP is detected by dialing a well-known external address.
func (l *Listener) URL() string {
	_, port, _ := net.SplitHostPort(l.addr)
	ip := outboundIP()
	return fmt.Sprintf("http://%s:%s", ip, port)
}

// Wait blocks until a callback arrives, the context is cancelled, or timeout elapses.
func (l *Listener) Wait(ctx context.Context, timeout time.Duration) (*Callback, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case cb := <-l.callbacks:
		return &cb, true
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

// Stop shuts down the HTTP server.
func (l *Listener) Stop(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.server == nil {
		return nil
	}
	return l.server.Shutdown(ctx)
}

func (l *Listener) handleCallback(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16)) //nolint:errcheck // best-effort; partial body still valuable
	cb := Callback{
		Method:  r.Method,
		URL:     r.RequestURI,
		Headers: r.Header.Clone(),
		Body:    body,
	}
	select {
	case l.callbacks <- cb:
	default:
		// Channel full — drop (shouldn't happen in practice with buffer=16)
	}
	w.WriteHeader(http.StatusOK)
}

// outboundIP returns the preferred outbound IP address of the current host.
// It dials a well-known external address (8.8.8.8:80) without actually sending data.
func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
