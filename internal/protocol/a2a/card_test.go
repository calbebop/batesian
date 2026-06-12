package a2a

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
