package oob

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestWaitForMarker_IgnoresStrayCallbacks verifies that a stray inbound request
// (no marker) does not consume the wait or get returned: the probe's own
// marker-bearing callback is delivered instead. Before WaitForMarker, the stray
// callback would be returned first and fire a false-positive SSRF finding.
func TestWaitForMarker_IgnoresStrayCallbacks(t *testing.T) {
	l := New()
	l.callbacks <- Callback{Method: "GET", URL: "/unrelated-scan"}
	l.callbacks <- Callback{Method: "POST", URL: "/batesian-abc123/jwks_uri"}

	cb, ok := l.WaitForMarker(context.Background(), time.Second, "batesian-abc123")
	if !ok {
		t.Fatal("expected the marker-matching callback to be delivered")
	}
	if cb.URL != "/batesian-abc123/jwks_uri" {
		t.Errorf("got callback %q, want the marker-bearing one", cb.URL)
	}
}

// TestWaitForMarker_NoMatchTimesOut verifies that a stray-only stream produces no
// hit, so an unrelated inbound request cannot be mistaken for a real callback.
func TestWaitForMarker_NoMatchTimesOut(t *testing.T) {
	l := New()
	l.callbacks <- Callback{Method: "GET", URL: "/stray-only"}

	if _, ok := l.WaitForMarker(context.Background(), 100*time.Millisecond, "batesian-xyz"); ok {
		t.Error("expected no hit when nothing matches the marker")
	}
}

// TestWaitForMarker_EmptyMarkerMatchesAny preserves the any-callback contract for
// an empty marker.
func TestWaitForMarker_EmptyMarkerMatchesAny(t *testing.T) {
	l := New()
	l.callbacks <- Callback{Method: "GET", URL: "/whatever"}

	if _, ok := l.WaitForMarker(context.Background(), time.Second, ""); !ok {
		t.Error("empty marker should match any callback")
	}
}

// TestListener_StopResetsLifecycle pins two contracts: URL() is empty before
// any Start (a half-formed callback URL handed to a target would register a
// probe that can never fire), and after Stop the listener is reusable - a
// second Start binds a fresh, answering server instead of reporting the dead
// one's address.
func TestListener_StopResetsLifecycle(t *testing.T) {
	l := New()
	if got := l.URL(); got != "" {
		t.Fatalf("URL before Start = %q, want empty", got)
	}

	url1, err := l.Start()
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if url1 == "" {
		t.Fatal("first start returned empty URL")
	}

	ctx := context.Background()
	if err := l.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := l.URL(); got != "" {
		t.Errorf("URL after Stop = %q, want empty", got)
	}

	url2, err := l.Start()
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if url2 == "" {
		t.Fatal("restart returned empty URL")
	}

	// The restarted server must actually answer.
	resp, err := http.Post(url2+"/probe", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post to restarted listener: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("restarted listener answered HTTP %d, want 200", resp.StatusCode)
	}

	if err := l.Stop(ctx); err != nil {
		t.Errorf("second stop: %v", err)
	}
}
