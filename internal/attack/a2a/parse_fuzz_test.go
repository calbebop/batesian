package a2a

import (
	"testing"
	"unicode/utf8"
)

// The helpers below all consume raw response bodies from the host being scanned.
// A hostile or simply broken target controls those bytes, so a panic in any of
// them is a scanner crash the target can trigger. These targets assert only that
// the parsers stay total: any input is either rejected or handled.

// FuzzParseAgentCardBody covers card decoding plus the declared-security reading
// that a2a-card-security-unenforced-001 gates its finding on. That rule only
// fires when the card declares required auth, so a parser that mis-handles an
// odd requirements list would change a security verdict, not just crash.
func FuzzParseAgentCardBody(f *testing.F) {
	f.Add([]byte(`{"name":"a","securityRequirements":[{"bearerAuth":[]}]}`))
	f.Add([]byte(`{"name":"a","security":[{"apiKey":["scope"]}]}`))
	f.Add([]byte(`{"name":"a","securityRequirements":[{},{"bearerAuth":[]}]}`)) // anonymous allowed
	f.Add([]byte(`{"name":"a","securityRequirements":[]}`))
	f.Add([]byte(`{"name":"a","securityRequirements":"not-a-list"}`))
	f.Add([]byte(`{"name":"a","securityRequirements":[null,1,"x"]}`))
	f.Add([]byte(`{"url":"http://h"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		card, ok := parseCard(data)
		if !ok {
			return
		}
		schemes, required := declaredAuthRequirement(card)
		// A requirement is only "required" when at least one scheme was named;
		// reporting required with no schemes would produce an evidence-free finding.
		if required && len(schemes) == 0 {
			t.Fatalf("declaredAuthRequirement reported required with no schemes: %q", data)
		}
		_ = cardSecurityList(card)
		_ = cardHasSignatures(card)
	})
}

// FuzzExtractTaskContext covers the task/context id extraction every A2A rule
// runs over a target's SendMessage response.
func FuzzExtractTaskContext(f *testing.F) {
	f.Add([]byte(`{"result":{"id":"t-1","contextId":"c-1"}}`))
	f.Add([]byte(`{"result":{"id":123,"contextId":null}}`))
	f.Add([]byte(`{"result":{"task":{"id":"t-2"}}}`))
	f.Add([]byte(`{"error":{"code":-32001,"message":"nope"}}`))
	f.Add([]byte(`{"result":[]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	// 65 bytes of multi-byte runes: byte 64 lands mid-rune.
	f.Add([]byte(`{"e":"éééééééééééééééééééééééééééééé"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = extractTaskContext(data)
		_ = isJSONRPCError(data)
		_ = bodyShowsCanceled(data)

		// snippet feeds Finding.Evidence, which is marshalled into JSON and SARIF.
		const limit = 64
		got := snippet(data, limit)
		// It may append a 3-byte ellipsis when it truncates, but no more.
		if len(got) > limit+len("...") {
			t.Fatalf("snippet exceeded its limit: got %d bytes for %q", len(got), data)
		}
		// Truncating valid UTF-8 must not produce invalid UTF-8: a split rune
		// would be silently rewritten to U+FFFD in the report output.
		if utf8.Valid(data) && !utf8.ValidString(got) {
			t.Fatalf("snippet split a rune: %q produced invalid UTF-8 %q", data, got)
		}
	})
}
