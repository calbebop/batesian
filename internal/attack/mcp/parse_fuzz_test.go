package mcp

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

// FuzzSnippetMCP covers the evidence truncation shared by the OAuth and token
// rules. Its input is the scanned target's raw response body, and its output
// lands in Finding.Evidence, which is marshalled into JSON and SARIF, so
// truncating valid UTF-8 must not yield invalid UTF-8: a split rune would be
// silently rewritten to U+FFFD in the report.
func FuzzSnippetMCP(f *testing.F) {
	f.Add([]byte(`{"error":"invalid_client"}`))
	f.Add([]byte(""))
	// 300 bytes is the truncation point; multi-byte runes straddle it.
	f.Add([]byte(`{"m":"` + string(make([]byte, 0)) + "ééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé" + `"}`))
	f.Add([]byte("\xff\xfe invalid utf8 prefix"))

	f.Fuzz(func(t *testing.T, data []byte) {
		got := snippetMCP(data)
		const limit = 300
		if len(got) > limit+len("...") {
			t.Fatalf("snippetMCP exceeded its limit: got %d bytes for %q", len(got), data)
		}
		if utf8.Valid(data) && !utf8.ValidString(got) {
			t.Fatalf("snippetMCP split a rune: %q produced invalid UTF-8 %q", data, got)
		}
	})
}

// These helpers all read JSON-RPC bodies returned by the server under test, so a
// hostile or broken target controls their input. Each target asserts the parsers
// stay total, and that the dispatch classifiers never claim an unauthenticated
// call succeeded on input that carries no such evidence.

// FuzzServerSupports covers capability detection, which every unauth rule gates
// on. A false positive here would make a rule probe a server that never
// advertised the capability; a false negative would silently skip a real target.
func FuzzServerSupports(f *testing.F) {
	f.Add([]byte(`{"result":{"capabilities":{"tools":{},"logging":{}}}}`))
	f.Add([]byte(`{"result":{"capabilities":{"completions":{}}}}`))
	f.Add([]byte(`{"result":{"capabilities":[]}}`))
	f.Add([]byte(`{"result":{"capabilities":null}}`))
	f.Add([]byte(`{"result":"tools"}`))
	f.Add([]byte(`{"instructions":"this server has tools and logging"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := mcpSession{RawInit: data}
		for _, capability := range []string{"tools", "logging", "completions", "prompts", "resources"} {
			supported := s.ServerSupports(capability)
			// Capabilities are read structurally, never by substring, so a body
			// that does not decode to an object cannot advertise anything.
			if supported {
				var probe struct {
					Result struct {
						Capabilities map[string]json.RawMessage `json:"capabilities"`
					} `json:"result"`
				}
				if err := json.Unmarshal(data, &probe); err != nil {
					t.Fatalf("ServerSupports(%q) was true for undecodable body %q", capability, data)
				}
				if _, ok := probe.Result.Capabilities[capability]; !ok {
					t.Fatalf("ServerSupports(%q) was true without that capability key: %q", capability, data)
				}
			}
		}
	})
}

// FuzzDispatchClassifiers covers the three "was this dispatched without auth"
// classifiers. They decide whether a confirmed finding is reported, so they must
// never treat an auth rejection or an undecodable body as a successful dispatch.
func FuzzDispatchClassifiers(f *testing.F) {
	f.Add([]byte(`{"error":{"code":-32602,"message":"Invalid params"}}`))
	f.Add([]byte(`{"error":{"code":-32603,"message":"invalid_value"}}`))
	f.Add([]byte(`{"error":{"code":-32601,"message":"Method not found"}}`))
	f.Add([]byte(`{"error":{"code":-32001,"message":"Unauthorized"}}`))
	f.Add([]byte(`{"result":{}}`))
	f.Add([]byte(`{"result":{"completion":{"values":["a","b"],"total":2}}}`))
	f.Add([]byte(`{"result":{"completion":{"values":[1,null,"c"]}}}`))
	f.Add([]byte(`{"error":"not-an-object"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var body map[string]interface{}
		if err := json.Unmarshal(data, &body); err != nil {
			return
		}
		for _, fn := range []func(map[string]interface{}) (bool, string){
			completionDispatchReachable,
			setLevelDispatchReachable,
			callDispatchReachable,
		} {
			reachable, reason := fn(body)
			// A positive verdict must always carry evidence for the report.
			if reachable && reason == "" {
				t.Fatalf("classifier reported reachable with no evidence for %q", data)
			}
		}
		// Value extraction and its evidence cap must hold for any shape.
		values := completionValues(body)
		if got := sampleValues(values); len(got) > 11 {
			t.Fatalf("sampleValues returned %d entries, above the cap, for %q", len(got), data)
		}
	})
}
