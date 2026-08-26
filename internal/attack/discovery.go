package attack

import (
	"sync"
)

// DiscoveryCache remembers, for the lifetime of one scan, which candidate
// path answered as MCP on each target base URL and whether a modern-era
// wire was seen there. Without it every MCP rule re-walks the same
// candidate list and re-issues the same discovery handshakes, so a scan
// over N rules floods a target with N-fold duplicated traffic - log noise,
// rate-limit bait, and avoidable latency.
//
// The engine allocates one cache per scan and hands it to executors through
// Options.Discovery. A nil cache is legal everywhere in this API: helpers
// treat it as always-miss, which restores the pre-cache behaviour for
// direct executor use in tests.
//
// Only positive resolutions are trusted across rules. Discovering that
// nothing answered is not remembered: a refusal observed by one rule under
// its own credentials must not silence the next rule's chance to see one,
// and probe-honesty depends on those refusals being re-observed live.
type DiscoveryCache struct {
	mu     sync.Mutex
	legacy map[string]string // baseURL -> endpoint that completed a handshake
	modern map[string]bool   // endpoint -> a modern wire answers there
}

// NewDiscoveryCache returns an empty scan-scoped cache.
func NewDiscoveryCache() *DiscoveryCache {
	return &DiscoveryCache{
		legacy: map[string]string{},
		modern: map[string]bool{},
	}
}

// LegacyEndpoint returns the endpoint known to complete a handshake for
// baseURL, if any earlier rule recorded one.
func (c *DiscoveryCache) LegacyEndpoint(baseURL string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ep, ok := c.legacy[baseURL]
	return ep, ok
}

// RememberLegacy records the endpoint that completed a handshake for baseURL.
func (c *DiscoveryCache) RememberLegacy(baseURL, endpoint string) {
	if c == nil || endpoint == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.legacy == nil {
		c.legacy = map[string]string{}
	}
	c.legacy[baseURL] = endpoint
}

// ModernPresent reports whether a earlier lookup established that the
// endpoint serves the modern wire. known is false when nobody has looked.
func (c *DiscoveryCache) ModernPresent(endpoint string) (present, known bool) {
	if c == nil {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	present, known = c.modern[endpoint]
	return present, known
}

// RememberModernPresent records the outcome of a modern-wire detection at
// endpoint, positive or negative, so later rules repeat neither the request
// nor the misreading of its absence.
func (c *DiscoveryCache) RememberModernPresent(endpoint string, present bool) {
	if c == nil || endpoint == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.modern == nil {
		c.modern = map[string]bool{}
	}
	c.modern[endpoint] = present
}
