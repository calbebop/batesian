package attack

import "testing"

func TestDiscoveryCacheRoundTrip(t *testing.T) {
	c := NewDiscoveryCache()

	if _, ok := c.LegacyEndpoint("http://x"); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.RememberLegacy("http://x", "http://x/mcp")
	ep, ok := c.LegacyEndpoint("http://x")
	if !ok || ep != "http://x/mcp" {
		t.Fatalf("want remembered endpoint, got %q ok=%v", ep, ok)
	}
	// Overwrite: a later successful walk may relocate the handler.
	c.RememberLegacy("http://x", "http://x/api")
	if ep, _ = c.LegacyEndpoint("http://x"); ep != "http://x/api" {
		t.Fatalf("want updated endpoint, got %q", ep)
	}
}

func TestDiscoveryCacheModernNegativesCached(t *testing.T) {
	c := NewDiscoveryCache()
	if _, known := c.ModernPresent("http://x/mcp"); known {
		t.Fatal("expected unknown on empty cache")
	}
	c.RememberModernPresent("http://x/mcp", false)
	present, known := c.ModernPresent("http://x/mcp")
	if !known || present {
		t.Fatalf("want cached negative (present=false, known=true), got %v/%v", present, known)
	}
}

// TestDiscoveryCacheNilSafe pins the contract that a nil cache behaves as an
// always-miss store: executors built outside the engine pass no cache and
// must keep working unchanged.
func TestDiscoveryCacheNilSafe(t *testing.T) {
	var c *DiscoveryCache
	if _, ok := c.LegacyEndpoint("http://x"); ok {
		t.Fatal("nil LegacyEndpoint must miss")
	}
	c.RememberLegacy("http://x", "http://x/mcp") // must not panic
	if _, known := c.ModernPresent("http://x"); known {
		t.Fatal("nil ModernPresent must be unknown")
	}
	c.RememberModernPresent("http://x", true) // must not panic
}
