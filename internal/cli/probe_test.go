package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/protocol/a2a"
)

// TestCardToProbeResult_ExtendedCardAndProtocol covers the two card fields whose
// v0.3 spellings probe could not see. ExtendedCardAvailable is not merely a
// printed row: probe gates two live checks of /extendedAgentCard on it, one of
// which fetches the endpoint with a fabricated Bearer token, so a v0.3 agent got
// neither.
func TestCardToProbeResult_ExtendedCardAndProtocol(t *testing.T) {
	tests := []struct {
		name         string
		fields       string
		wantExtended bool
		wantProtocol string
		why          string
	}{
		{
			name:         "v0.3 card",
			fields:       `"protocolVersion":"0.3.0","supportsAuthenticatedExtendedCard":true`,
			wantExtended: true,
			wantProtocol: "0.3.0",
			why:          "this is what a2a-go serves, and probe skipped both extended-card checks",
		},
		{
			name:         "v1.0 card",
			fields:       `"protocolVersion":"1.0","capabilities":{"extendedAgentCard":true}`,
			wantExtended: true,
			wantProtocol: "1.0",
			why:          "the v1.0 path must be unaffected",
		},
		{
			name:         "no extended card, no protocol declared",
			fields:       `"capabilities":{"streaming":true}`,
			wantExtended: false,
			wantProtocol: "",
			why:          "probe must not claim an extended card that was never advertised",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"name":"Agent","description":"d","version":"9.9.9","url":"http://127.0.0.1:1/",` +
				`"preferredTransport":"JSONRPC","skills":[],` + tt.fields + `}`
			var card a2a.AgentCard
			if err := json.Unmarshal([]byte(body), &card); err != nil {
				t.Fatalf("card must parse: %v", err)
			}

			got := cardToProbeResult(&card, time.Millisecond)
			if got.ExtendedCardAvailable != tt.wantExtended {
				t.Errorf("ExtendedCardAvailable = %v, want %v (%s)",
					got.ExtendedCardAvailable, tt.wantExtended, tt.why)
			}
			if got.ProtocolVersion != tt.wantProtocol {
				t.Errorf("ProtocolVersion = %q, want %q", got.ProtocolVersion, tt.wantProtocol)
			}
			// The agent version and the protocol version are different things and
			// must not be conflated in the output.
			if got.Version != "9.9.9" {
				t.Errorf("Version = %q, want the agent version 9.9.9", got.Version)
			}
		})
	}
}

// The Authentication block probe prints is built here, so this is where a
// regression in what it reads would show up. The unit tests on AgentCard cover
// the card semantics; these cover that cardToProbeResult actually asks the card
// rather than reaching for one version's field.
func TestCardToProbeResult_AuthAcrossCardVersions(t *testing.T) {
	tests := []struct {
		name           string
		security       string
		wantAuth       bool
		wantSchemeText string
		why            string
	}{
		{
			name: "v0.3 card, native shape",
			security: `"security":[{"bearerAuth":["a2a:invoke"]}],` +
				`"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer","bearerFormat":"opaque"}}`,
			wantAuth:       true,
			wantSchemeText: "bearerAuth (http/bearer)",
			why:            "this is what the official Go SDK serves, and probe reported it as unauthenticated",
		},
		{
			name: "v1.0 card, native shape",
			security: `"securityRequirements":[{"schemes":{"bearerAuth":{"list":["a2a:invoke"]}}}],` +
				`"securitySchemes":{"bearerAuth":{"httpAuthSecurityScheme":{"scheme":"bearer"}}}`,
			wantAuth:       true,
			wantSchemeText: "bearerAuth (http/bearer)",
			why:            "the v1.0 path must be unaffected",
		},
		{
			name:     "no security declared",
			security: `"description2":"none"`,
			wantAuth: false,
			why:      "an agent declaring nothing is reported as unauthenticated, which is accurate",
		},
		{
			name:     "v0.3 card permitting anonymous access",
			security: `"security":[{},{"bearerAuth":[]}]`,
			wantAuth: false,
			why:      "an empty requirement object explicitly permits anonymous access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"name":"Agent","description":"d","version":"1.0.0","url":"http://127.0.0.1:1/",` +
				`"preferredTransport":"JSONRPC","capabilities":{},"skills":[],` + tt.security + `}`
			var card a2a.AgentCard
			if err := json.Unmarshal([]byte(body), &card); err != nil {
				t.Fatalf("card must parse: %v", err)
			}

			got := cardToProbeResult(&card, time.Millisecond)
			if got.AuthRequired != tt.wantAuth {
				t.Errorf("AuthRequired = %v, want %v (%s)", got.AuthRequired, tt.wantAuth, tt.why)
			}
			if tt.wantSchemeText == "" {
				return
			}
			joined := strings.Join(got.SecuritySchemes, ", ")
			if joined != tt.wantSchemeText {
				t.Errorf("SecuritySchemes = %q, want %q", joined, tt.wantSchemeText)
			}
		})
	}
}
