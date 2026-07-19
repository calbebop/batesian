package a2a

import (
	"encoding/json"
	"testing"
)

// FuzzAgentCardParse exercises agent-card decoding and service-URL selection with
// arbitrary input. A scan target controls the bytes served at the well-known card
// path, so a panic here is a scanner crash triggerable by the host being scanned.
// GetServiceURL parses attacker-controlled URL strings, which makes it the most
// interesting reachable surface in this type.
func FuzzAgentCardParse(f *testing.F) {
	f.Add([]byte(minimalV1CardJSON))
	f.Add([]byte(legacyV03CardJSON))
	f.Add([]byte(fullV1CardJSON))
	f.Add([]byte(`{"supportedInterfaces":[{"url":"http://h/a","protocolBinding":"JSONRPC"}]}`))
	f.Add([]byte(`{"url":"::not a url::","preferredTransport":"JSONRPC"}`))
	f.Add([]byte(`{"securityRequirements":[{}],"securitySchemes":{}}`))
	f.Add([]byte(`{"security":[{"apiKey":[]}]}`))
	f.Add([]byte(`{"supportedInterfaces":[{"url":"%zz","protocolBinding":"JSONRPC"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var card AgentCard
		if err := json.Unmarshal(data, &card); err != nil {
			return // not JSON, or not shaped like a card: nothing to exercise
		}
		// Must not panic on any decodable card, however malformed its fields.
		_ = card.GetServiceURL()
		for name, scheme := range card.SecuritySchemes {
			_ = name
			_ = scheme.Type()
		}
		for _, req := range card.SecurityRequirements {
			for k, v := range req {
				_, _ = k, v
			}
		}
		for _, req := range card.Security {
			for k, v := range req {
				_, _ = k, v
			}
		}
	})
}
