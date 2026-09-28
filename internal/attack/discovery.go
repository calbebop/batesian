package attack

import (
	"sync"
)

// DiscoveryCache remembers successful legacy endpoint resolution for one scan.
// Modern discovery is credential-sensitive and is never cached across rules.
// A nil cache behaves as an always-miss store.
type DiscoveryCache struct {
	mu     sync.Mutex
	legacy map[string]string // baseURL -> endpoint that completed a handshake
}

// NewDiscoveryCache returns an empty scan-scoped cache.
func NewDiscoveryCache() *DiscoveryCache {
	return &DiscoveryCache{
		legacy: map[string]string{},
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
