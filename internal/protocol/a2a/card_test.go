package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// minimalV1CardJSON is the smallest valid v1.0 Agent Card (matches hello-world sample shape).
const minimalV1CardJSON = `{
	"name": "Hello World Agent",
	"description": "A minimal test agent",
	"version": "1.0.0",
	"supportedInterfaces": [
		{
			"url": "http://localhost:9999",
			"protocolBinding": "JSONRPC",
			"protocolVersion": "1.0"
		}
	],
	"capabilities": {
		"streaming": true
	},
	"defaultInputModes": ["text/plain"],
	"defaultOutputModes": ["text/plain"],
	"skills": [
		{
			"id": "hello",
			"name": "Hello",
			"description": "Says hello",
			"tags": ["hello"]
		}
	]
}`

// legacyV03CardJSON exercises the v0.3 top-level url field.
const legacyV03CardJSON = `{
	"name": "Legacy Agent",
	"description": "A v0.3 agent",
	"url": "https://legacy.example.com",
	"version": "0.3.0",
	"capabilities": {},
	"skills": [
		{
			"id": "task",
			"name": "Task",
			"description": "Performs a task",
			"tags": []
		}
	]
}`

// fullV1CardJSON exercises all fields including attack-relevant ones.
const fullV1CardJSON = `{
	"name": "Research Assistant",
	"description": "An AI research agent",
	"version": "2.0.0",
	"supportedInterfaces": [
		{
			"url": "https://agent.example.com/a2a/v1",
			"protocolBinding": "HTTP+JSON",
			"protocolVersion": "1.0"
		}
	],
	"provider": {
		"organization": "Example Corp",
		"url": "https://example.com"
	},
	"capabilities": {
		"streaming": true,
		"pushNotifications": true,
		"extendedAgentCard": true
	},
	"securitySchemes": {
		"bearerAuth": {
			"httpAuthSecurityScheme": {
				"scheme": "Bearer",
				"bearerFormat": "JWT"
			}
		},
		"oauth2Flow": {
			"oauth2SecurityScheme": {
				"flows": {
					"authorizationCode": {
						"authorizationUrl": "https://auth.example.com/authorize",
						"tokenUrl": "https://auth.example.com/token",
						"scopes": {
							"tasks:read": "Read tasks",
							"tasks:write": "Write tasks"
						},
						"pkceRequired": true
					}
				}
			}
		}
	},
	"securityRequirements": [{"bearerAuth": []}],
	"defaultInputModes": ["text/plain", "application/json"],
	"defaultOutputModes": ["application/json"],
	"skills": [
		{
			"id": "research",
			"name": "Research",
			"description": "Finds and summarizes information",
			"tags": ["research", "nlp"],
			"examples": ["Research climate change"],
			"inputModes": ["text/plain"],
			"outputModes": ["text/plain"]
		}
	]
}`

func TestAgentCard_MinimalV1(t *testing.T) {
	var card AgentCard
	if err := json.Unmarshal([]byte(minimalV1CardJSON), &card); err != nil {
		t.Fatalf("failed to parse minimal v1 card: %v", err)
	}
	if card.Name != "Hello World Agent" {
		t.Errorf("Name = %q", card.Name)
	}
	if len(card.SupportedInterfaces) != 1 {
		t.Fatalf("SupportedInterfaces len = %d, want 1", len(card.SupportedInterfaces))
	}
	if card.SupportedInterfaces[0].URL != "http://localhost:9999" {
		t.Errorf("SupportedInterfaces[0].URL = %q", card.SupportedInterfaces[0].URL)
	}
	if card.GetServiceURL() != "http://localhost:9999" {
		t.Errorf("GetServiceURL() = %q", card.GetServiceURL())
	}
	if !card.Capabilities.Streaming {
		t.Error("Capabilities.Streaming should be true")
	}
}

func TestAgentCard_LegacyV03URL(t *testing.T) {
	var card AgentCard
	if err := json.Unmarshal([]byte(legacyV03CardJSON), &card); err != nil {
		t.Fatalf("failed to parse legacy v0.3 card: %v", err)
	}
	// v0.3 card has no supportedInterfaces but has top-level url
	if len(card.SupportedInterfaces) != 0 {
		t.Errorf("SupportedInterfaces should be empty for v0.3 card, got %d", len(card.SupportedInterfaces))
	}
	if card.URL != "https://legacy.example.com" {
		t.Errorf("URL = %q", card.URL)
	}
	// GetServiceURL should fall back to legacy url field
	if card.GetServiceURL() != "https://legacy.example.com" {
		t.Errorf("GetServiceURL() = %q, want legacy URL", card.GetServiceURL())
	}
}

// TestGetServiceURL_SelectsJSONRPCNotFirstGRPC mirrors the official a2a-python
// reference card: gRPC is listed first (scheme-less) and is the preferred/top-level
// transport, but GetServiceURL must return the JSON-RPC interface, not the gRPC one.
func TestGetServiceURL_SelectsJSONRPCNotFirstGRPC(t *testing.T) {
	const cardJSON = `{
		"name": "Sample Agent",
		"supportedInterfaces": [
			{"url": "127.0.0.1:50051", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
			{"url": "http://127.0.0.1:41241/a2a/jsonrpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
		],
		"additionalInterfaces": [
			{"transport": "JSONRPC", "url": "http://127.0.0.1:41241/a2a/jsonrpc"}
		],
		"preferredTransport": "GRPC",
		"url": "127.0.0.1:50052"
	}`
	var card AgentCard
	if err := json.Unmarshal([]byte(cardJSON), &card); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := card.GetServiceURL(); got != "http://127.0.0.1:41241/a2a/jsonrpc" {
		t.Errorf("GetServiceURL() = %q, want the JSON-RPC interface (not the first/gRPC one)", got)
	}
}

// TestGetServiceURL_V03AdditionalInterfaces selects the JSON-RPC entry from a v0.3
// card's additionalInterfaces when no v1.0 supportedInterfaces JSON-RPC exists.
func TestGetServiceURL_V03AdditionalInterfaces(t *testing.T) {
	const cardJSON = `{
		"name": "Legacy",
		"additionalInterfaces": [
			{"transport": "HTTP+JSON", "url": "http://h/rest"},
			{"transport": "JSONRPC", "url": "http://h/jr"}
		],
		"preferredTransport": "GRPC",
		"url": "h:50052"
	}`
	var card AgentCard
	if err := json.Unmarshal([]byte(cardJSON), &card); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := card.GetServiceURL(); got != "http://h/jr" {
		t.Errorf("GetServiceURL() = %q, want http://h/jr", got)
	}
}

func TestAgentCard_FullV1(t *testing.T) {
	var card AgentCard
	if err := json.Unmarshal([]byte(fullV1CardJSON), &card); err != nil {
		t.Fatalf("failed to parse full v1 card: %v", err)
	}

	if !card.Capabilities.PushNotifications {
		t.Error("Capabilities.PushNotifications should be true")
	}
	if !card.Capabilities.ExtendedAgentCard {
		t.Error("Capabilities.ExtendedAgentCard should be true")
	}

	// SecuritySchemes - discriminated union
	if len(card.SecuritySchemes) != 2 {
		t.Errorf("SecuritySchemes len = %d, want 2", len(card.SecuritySchemes))
	}
	bearer, ok := card.SecuritySchemes["bearerAuth"]
	if !ok || bearer.HTTPAuth == nil {
		t.Fatal("bearerAuth scheme missing or wrong type")
	}
	if bearer.Type() != "http/Bearer" {
		t.Errorf("bearer.Type() = %q, want %q", bearer.Type(), "http/Bearer")
	}
	if bearer.HTTPAuth.BearerFormat != "JWT" {
		t.Errorf("BearerFormat = %q, want JWT", bearer.HTTPAuth.BearerFormat)
	}

	oauth, ok := card.SecuritySchemes["oauth2Flow"]
	if !ok || oauth.OAuth2 == nil {
		t.Fatal("oauth2Flow scheme missing or wrong type")
	}
	if oauth.Type() != "oauth2" {
		t.Errorf("oauth.Type() = %q", oauth.Type())
	}
	if oauth.OAuth2.Flows.AuthorizationCode == nil {
		t.Fatal("AuthorizationCode flow is nil")
	}
	if !oauth.OAuth2.Flows.AuthorizationCode.PKCERequired {
		t.Error("PKCERequired should be true")
	}

	// SecurityRequirements
	if len(card.SecurityRequirements) == 0 {
		t.Error("SecurityRequirements should be non-empty")
	}
}

// TestAgentCard_V03SecurityField verifies the v0.3 spelling of the requirements
// list (`security`) parses, not only the v1.0 `securityRequirements`.
func TestAgentCard_V03SecurityField(t *testing.T) {
	const v03SecuredCard = `{
		"name": "Secured Legacy Agent",
		"url": "https://legacy.example.com",
		"version": "0.3.0",
		"capabilities": {},
		"skills": [],
		"securitySchemes": {"apiKey": {"apiKeySecurityScheme": {"location": "header", "name": "X-API-Key"}}},
		"security": [{"apiKey": []}]
	}`
	var card AgentCard
	if err := json.Unmarshal([]byte(v03SecuredCard), &card); err != nil {
		t.Fatalf("failed to parse v0.3 secured card: %v", err)
	}
	if len(card.Security) != 1 {
		t.Fatalf("Security (v0.3) len = %d, want 1", len(card.Security))
	}
	if _, ok := card.Security[0]["apiKey"]; !ok {
		t.Errorf("Security[0] should reference the apiKey scheme, got %v", card.Security[0])
	}
	if len(card.SecurityRequirements) != 0 {
		t.Errorf("SecurityRequirements should be empty for a v0.3 card, got %d", len(card.SecurityRequirements))
	}
}

// TestAgentCard_V1SecurityRequirementShapes covers the requirement entry shapes a
// card can arrive in. The nested one is what both official SDKs serve, and
// decoding straight into map[string][]string rejected it, which failed the whole
// card because FetchAgentCard treats an unmarshal error as fatal.
func TestAgentCard_V1SecurityRequirementShapes(t *testing.T) {
	tests := []struct {
		name       string
		entry      string
		wantScheme string
		wantScopes []string
		wantEmpty  bool
		why        string
	}{
		{
			name:       "v1.0 nested proto shape",
			entry:      `{"schemes":{"bearerAuth":{"list":["a2a:invoke"]}}}`,
			wantScheme: "bearerAuth",
			wantScopes: []string{"a2a:invoke"},
			why:        "SecurityRequirement is a proto message holding a schemes map of StringList",
		},
		{
			name:       "v1.0 nested, no scopes",
			entry:      `{"schemes":{"bearerAuth":{"list":[]}}}`,
			wantScheme: "bearerAuth",
			why:        "a required scheme need not demand any scope",
		},
		{
			name:       "OpenAPI-flat shape",
			entry:      `{"bearerAuth":["a2a:invoke"]}`,
			wantScheme: "bearerAuth",
			wantScopes: []string{"a2a:invoke"},
			why:        "v0.3 cards and hand-rolled v1.0 cards use the flat shape",
		},
		{
			name:      "empty entry",
			entry:     `{}`,
			wantEmpty: true,
			why:       "an entry naming no scheme requires nothing",
		},
		{
			name:      "empty schemes map",
			entry:     `{"schemes":{}}`,
			wantEmpty: true,
			why:       "the v1.0 spelling of the same statement",
		},
		{
			// A v0.3 card may name a scheme "schemes". Its value is a scope array
			// rather than an object, which is what tells the shapes apart.
			name:       "flat scheme literally named schemes",
			entry:      `{"schemes":["read"]}`,
			wantScheme: "schemes",
			wantScopes: []string{"read"},
			why:        "the shapes are distinguished by structure, not by the key name",
		},
		{
			name:      "entry is not an object",
			entry:     `"bearerAuth"`,
			wantEmpty: true,
			why:       "one malformed optional field must not sink an otherwise valid card",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"name":"Agent","description":"d","version":"1.0.0","capabilities":{},"skills":[],` +
				`"securityRequirements":[` + tt.entry + `]}`
			var card AgentCard
			if err := json.Unmarshal([]byte(body), &card); err != nil {
				t.Fatalf("card must parse (%s): %v", tt.why, err)
			}
			if card.Name != "Agent" {
				t.Errorf("the rest of the card must survive, got name %q", card.Name)
			}
			if len(card.SecurityRequirements) != 1 {
				t.Fatalf("SecurityRequirements len = %d, want 1", len(card.SecurityRequirements))
			}
			got := card.SecurityRequirements[0]
			if tt.wantEmpty {
				if len(got) != 0 {
					t.Errorf("requirement = %v, want empty (%s)", got, tt.why)
				}
				return
			}
			scopes, present := got[tt.wantScheme]
			if !present {
				t.Fatalf("requirement %v does not name %q (%s)", got, tt.wantScheme, tt.why)
			}
			if len(scopes) != len(tt.wantScopes) {
				t.Errorf("scopes = %v, want %v", scopes, tt.wantScopes)
			}
			for i := range tt.wantScopes {
				if i < len(scopes) && scopes[i] != tt.wantScopes[i] {
					t.Errorf("scopes = %v, want %v", scopes, tt.wantScopes)
					break
				}
			}
		})
	}
}

// TestFetchAgentCard_RealV1SecuredCard is the regression at the level the bug was
// reported: probe fetching a real secured agent's card. It previously failed with
// "is not valid JSON", so probe told the operator a correctly configured agent
// was not an A2A agent.
func TestFetchAgentCard_RealV1SecuredCard(t *testing.T) {
	const securedCard = `{
		"name": "Secured Echo Agent",
		"description": "Agent that enforces bearer authorization",
		"version": "1.0.0",
		"capabilities": {"streaming": true},
		"skills": [{"id": "echo", "name": "Echo", "description": "Echoes", "tags": ["echo"]}],
		"supportedInterfaces": [{"url": "https://agent.example.com/", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
		"securitySchemes": {"bearerAuth": {"httpAuthSecurityScheme": {"scheme": "bearer"}}},
		"securityRequirements": [{"schemes": {"bearerAuth": {"list": ["a2a:invoke"]}}}]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(securedCard))
	}))
	defer srv.Close()

	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	card, _, err := client.FetchAgentCard(context.Background())
	if err != nil {
		t.Fatalf("a real v1.0 secured card must be fetchable: %v", err)
	}
	if card.Name != "Secured Echo Agent" {
		t.Errorf("Name = %q", card.Name)
	}
	// This is what probe reports as "auth required".
	if len(card.SecurityRequirements) == 0 {
		t.Error("SecurityRequirements is empty, so probe would report the agent as unauthenticated")
	}
	if _, ok := card.SecurityRequirements[0]["bearerAuth"]; !ok {
		t.Errorf("requirement should name bearerAuth, got %v", card.SecurityRequirements[0])
	}
}

// TestAgentCard_RequiresAuth covers what probe reports in its Authentication
// block. Reading only the v1.0 securityRequirements field described every v0.3
// agent as "no (unauthenticated access)", including ones that reject anonymous
// callers with 401.
func TestAgentCard_RequiresAuth(t *testing.T) {
	tests := []struct {
		name string
		sec  string
		want bool
		why  string
	}{
		{
			name: "v0.3 security field",
			sec:  `"security":[{"bearerAuth":["a2a:invoke"]}]`,
			want: true,
			why:  "a native v0.3 implementation declares auth here and nowhere else",
		},
		{
			name: "v1.0 securityRequirements, nested",
			sec:  `"securityRequirements":[{"schemes":{"bearerAuth":{"list":["a2a:invoke"]}}}]`,
			want: true,
			why:  "the v1.0 spelling must keep working",
		},
		{
			name: "both fields present",
			sec:  `"securityRequirements":[{"schemes":{"bearerAuth":{"list":[]}}}],"security":[{}]`,
			want: true,
			why:  "v1.0 takes precedence when a card carries both",
		},
		{
			name: "no declaration",
			sec:  `"name2":"x"`,
			want: false,
			why:  "nothing declared means nothing required",
		},
		{
			name: "v0.3 with an anonymous alternative",
			sec:  `"security":[{},{"bearerAuth":[]}]`,
			want: false,
			why:  "an empty requirement object explicitly permits anonymous access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"name":"Agent","description":"d","version":"1.0.0","capabilities":{},"skills":[],` + tt.sec + `}`
			var card AgentCard
			if err := json.Unmarshal([]byte(body), &card); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := card.RequiresAuth(); got != tt.want {
				t.Errorf("RequiresAuth() = %v, want %v (%s)", got, tt.want, tt.why)
			}
		})
	}
}

// TestSecurityScheme_V03FlatForm covers the OpenAPI flat form a v0.3 card serves.
// The shapes are the ones the official Go SDK emits, which is a native v0.3
// implementation. Before this, every member stayed nil and Type() reported
// "unknown", so probe could not name the scheme an agent declared.
func TestSecurityScheme_V03FlatForm(t *testing.T) {
	tests := []struct {
		name     string
		scheme   string
		wantType string
	}{
		{"http bearer", `{"type":"http","scheme":"bearer","bearerFormat":"opaque"}`, "http/bearer"},
		{"http basic", `{"type":"http","scheme":"basic"}`, "http/basic"},
		{"apiKey", `{"type":"apiKey","in":"header","name":"X-API-Key"}`, "apiKey"},
		{"oauth2", `{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://idp/token","scopes":{}}}}`, "oauth2"},
		{"openIdConnect", `{"type":"openIdConnect","openIdConnectUrl":"https://idp/.well-known/openid-configuration"}`, "openIdConnect"},
		{"mutualTLS", `{"type":"mutualTLS"}`, "mtls"},
		// The v1.0 nested form must be unaffected.
		{"v1.0 nested http", `{"httpAuthSecurityScheme":{"scheme":"bearer"}}`, "http/bearer"},
		{"v1.0 nested apiKey", `{"apiKeySecurityScheme":{"location":"header","name":"X-API-Key"}}`, "apiKey"},
		// An unreadable scheme must not fail the card.
		{"unrecognized type", `{"type":"quantum"}`, "unknown"},
		{"not an object", `"bearer"`, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"name":"Agent","description":"d","version":"1.0.0","capabilities":{},"skills":[],` +
				`"securitySchemes":{"s":` + tt.scheme + `}}`
			var card AgentCard
			if err := json.Unmarshal([]byte(body), &card); err != nil {
				t.Fatalf("card must parse: %v", err)
			}
			if card.Name != "Agent" {
				t.Errorf("the rest of the card must survive, got name %q", card.Name)
			}
			scheme, ok := card.SecuritySchemes["s"]
			if !ok {
				t.Fatal("scheme missing from the map")
			}
			if got := scheme.Type(); got != tt.wantType {
				t.Errorf("Type() = %q, want %q", got, tt.wantType)
			}
		})
	}
}

// TestSecurityScheme_V03APIKeyLocation: v0.3 names the location "in", v1.0 names
// it "location". Both must land in the same field, since that is what an operator
// needs in order to know where the key goes.
func TestSecurityScheme_V03APIKeyLocation(t *testing.T) {
	for name, scheme := range map[string]string{
		"v0.3 in":       `{"type":"apiKey","in":"cookie","name":"sid"}`,
		"v1.0 location": `{"apiKeySecurityScheme":{"location":"cookie","name":"sid"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var s SecurityScheme
			if err := json.Unmarshal([]byte(scheme), &s); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if s.APIKey == nil {
				t.Fatal("APIKey member not populated")
			}
			if s.APIKey.Location != "cookie" {
				t.Errorf("Location = %q, want cookie", s.APIKey.Location)
			}
		})
	}
}

// TestAgentCard_SupportsExtendedCard covers both dialects' spelling of the
// extended-card advertisement. probe gates two of its own checks on this, one of
// them the fabricated-Bearer-token fetch, so reading only the v1.0 spelling meant
// neither ran against a v0.3 agent.
func TestAgentCard_SupportsExtendedCard(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
		why  string
	}{
		{
			name: "v0.3 top-level flag",
			body: `"supportsAuthenticatedExtendedCard":true`,
			want: true,
			why:  "v0.3 advertises it at the card top level, which is what a2a-go serves",
		},
		{
			name: "v1.0 nested flag",
			body: `"capabilities":{"extendedAgentCard":true}`,
			want: true,
			why:  "v1.0 moved it under capabilities",
		},
		{
			name: "both spellings",
			body: `"supportsAuthenticatedExtendedCard":true,"capabilities":{"extendedAgentCard":true}`,
			want: true,
			why:  "a card carrying both still advertises one extended card",
		},
		{
			name: "neither",
			body: `"capabilities":{"streaming":true}`,
			want: false,
			why:  "no advertisement means probe must not claim one",
		},
		{
			name: "v0.3 flag explicitly false",
			body: `"supportsAuthenticatedExtendedCard":false`,
			want: false,
			why:  "an explicit false is still no advertisement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"name":"Agent","description":"d","version":"1.0.0","skills":[],` + tt.body + `}`
			var card AgentCard
			if err := json.Unmarshal([]byte(body), &card); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := card.SupportsExtendedCard(); got != tt.want {
				t.Errorf("SupportsExtendedCard() = %v, want %v (%s)", got, tt.want, tt.why)
			}
		})
	}
}

// TestAgentCard_ProtocolVersionCaptured guards the field being read at all.
// buildJSONOutput re-marshals the parsed card, so a field the struct does not
// capture is dropped from probe's JSON output as well as its table.
func TestAgentCard_ProtocolVersionCaptured(t *testing.T) {
	const v03 = `{"name":"Agent","description":"d","version":"1.0.0","protocolVersion":"0.3.0",
		"url":"http://127.0.0.1:1/","preferredTransport":"JSONRPC","capabilities":{},"skills":[]}`
	var card AgentCard
	if err := json.Unmarshal([]byte(v03), &card); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if card.ProtocolVersion != "0.3.0" {
		t.Errorf("ProtocolVersion = %q, want %q", card.ProtocolVersion, "0.3.0")
	}
	// The JSON output path round-trips the card, so the field must survive that.
	raw, err := json.Marshal(&card)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"protocolVersion":"0.3.0"`) {
		t.Errorf("protocolVersion did not survive the round trip: %s", raw)
	}
}

func TestAgentCard_RoundTrip(t *testing.T) {
	var card AgentCard
	if err := json.Unmarshal([]byte(fullV1CardJSON), &card); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var card2 AgentCard
	if err := json.Unmarshal(out, &card2); err != nil {
		t.Fatalf("second unmarshal: %v", err)
	}
	if card.Name != card2.Name {
		t.Errorf("round-trip Name: %q vs %q", card.Name, card2.Name)
	}
	if card.GetServiceURL() != card2.GetServiceURL() {
		t.Errorf("round-trip GetServiceURL: %q vs %q", card.GetServiceURL(), card2.GetServiceURL())
	}
}

func TestNewClient_InvalidURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://agent.example.com", false},
		{"http://localhost:8080", false},
		{"not-a-url", true},
		{"ftp://example.com", true},
		{"", true},
	}
	for _, tt := range tests {
		_, err := NewClient(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewClient(%q): error = %v, wantErr = %v", tt.url, err, tt.wantErr)
		}
	}
}

func TestFetchAgentCard_V1Path(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == WellKnownPath {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(minimalV1CardJSON)) //nolint:errcheck
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	card, result, err := client.FetchAgentCard(t.Context())
	if err != nil {
		t.Fatalf("FetchAgentCard: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d", result.StatusCode)
	}
	if card.Name != "Hello World Agent" {
		t.Errorf("Name = %q", card.Name)
	}
}

func TestFetchAgentCard_LegacyFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only serve the legacy v0.3 path
		if r.URL.Path == WellKnownPathLegacy {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(legacyV03CardJSON)) //nolint:errcheck
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	card, _, err := client.FetchAgentCard(t.Context())
	if err != nil {
		t.Fatalf("FetchAgentCard should fall back to legacy path: %v", err)
	}
	if card.Name != "Legacy Agent" {
		t.Errorf("Name = %q", card.Name)
	}
}

func TestFetchAgentCard_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, _, err = client.FetchAgentCard(t.Context())
	if err == nil {
		t.Fatal("expected error for 404 on both paths, got nil")
	}
}
