package oob

import (
	"context"
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
