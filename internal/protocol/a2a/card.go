// Package a2a provides types and a client for the Agent-to-Agent (A2A) protocol.
// Spec reference: https://a2a-protocol.org/latest/specification/
package a2a

// AgentCard is the agent's public identity document.
// Served at GET /.well-known/agent-card.json (v1.0) or /.well-known/agent.json (v0.3 legacy).
type AgentCard struct {
	// Required fields (v1.0)
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Version      string            `json:"version"`
	Capabilities AgentCapabilities `json:"capabilities"`
	Skills       []AgentSkill      `json:"skills"`

	// SupportedInterfaces lists the A2A service endpoints for this agent (v1.0).
	// The first entry is the preferred endpoint.
	SupportedInterfaces []AgentInterface `json:"supportedInterfaces,omitempty"`

	// URL is the v0.3 top-level service URL field. Still present in many deployed agents.
	// Prefer SupportedInterfaces[0].URL when present.
	URL string `json:"url,omitempty"`

	// Required content-type defaults
	DefaultInputModes  []string `json:"defaultInputModes,omitempty"`
	DefaultOutputModes []string `json:"defaultOutputModes,omitempty"`

	// Optional metadata
	DocumentationURL string         `json:"documentationUrl,omitempty"`
	Provider         *AgentProvider `json:"provider,omitempty"`
	IconURL          string         `json:"iconUrl,omitempty"`

	// Authentication (OpenAPI-style security schemes)
	SecuritySchemes      map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	SecurityRequirements []SecurityRequirement     `json:"securityRequirements,omitempty"`

	// Signatures holds JWS signatures over the Agent Card (RFC 7515).
	Signatures []AgentCardSignature `json:"signatures,omitempty"`
}

// GetServiceURL returns the primary service URL, handling both v1.0 and v0.3 cards.
func (c *AgentCard) GetServiceURL() string {
	if len(c.SupportedInterfaces) > 0 {
		return c.SupportedInterfaces[0].URL
	}
	return c.URL
}

// AgentInterface describes a single A2A service endpoint (v1.0).
type AgentInterface struct {
	URL             string `json:"url"`             // required; absolute HTTPS URL
	ProtocolBinding string `json:"protocolBinding"` // required; "JSONRPC" | "GRPC" | "HTTP+JSON"
	ProtocolVersion string `json:"protocolVersion"` // required; e.g. "1.0"
	Tenant          string `json:"tenant,omitempty"`
}

// AgentProvider describes the organization operating the agent.
type AgentProvider struct {
	Organization string `json:"organization"` // required
	URL          string `json:"url,omitempty"`
}

// AgentCapabilities declares optional protocol features the agent supports.
// All fields default to false when absent.
type AgentCapabilities struct {
	Streaming         bool             `json:"streaming,omitempty"`
	PushNotifications bool             `json:"pushNotifications,omitempty"`
	ExtendedAgentCard bool             `json:"extendedAgentCard,omitempty"`
	Extensions        []AgentExtension `json:"extensions,omitempty"`
}

// AgentExtension represents a non-standard capability extension.
type AgentExtension struct {
	URI         string                 `json:"uri,omitempty"`
	Description string                 `json:"description,omitempty"`
	Required    bool                   `json:"required,omitempty"`
	Params      map[string]interface{} `json:"params,omitempty"`
}

// AgentSkill describes a task the agent can perform.
type AgentSkill struct {
	ID          string   `json:"id"`          // required; unique within the agent
	Name        string   `json:"name"`        // required
	Description string   `json:"description"` // required
	Tags        []string `json:"tags"`        // required; keywords

	Examples             []string              `json:"examples,omitempty"`
	InputModes           []string              `json:"inputModes,omitempty"`
	OutputModes          []string              `json:"outputModes,omitempty"`
	SecurityRequirements []SecurityRequirement `json:"securityRequirements,omitempty"`
}

// SecurityRequirement maps scheme names to required OAuth scopes.
// An empty slice means the scheme is required but no specific scopes are needed.
type SecurityRequirement map[string][]string

// SecurityScheme is a discriminated union — exactly one nested scheme object is populated.
// The discriminant is the JSON key name itself (apiKeySecurityScheme, httpAuthSecurityScheme, etc.),
// not a "type" field. This matches the A2A v1.0 specification.
type SecurityScheme struct {
	APIKey        *APIKeySecurityScheme        `json:"apiKeySecurityScheme,omitempty"`
	HTTPAuth      *HTTPAuthSecurityScheme      `json:"httpAuthSecurityScheme,omitempty"`
	OAuth2        *OAuth2SecurityScheme        `json:"oauth2SecurityScheme,omitempty"`
	OpenIDConnect *OpenIDConnectSecurityScheme `json:"openIdConnectSecurityScheme,omitempty"`
	MTLS          *MutualTLSSecurityScheme     `json:"mtlsSecurityScheme,omitempty"`
}

// Type returns a human-readable string describing the scheme type.
func (s *SecurityScheme) Type() string {
	switch {
	case s.APIKey != nil:
		return "apiKey"
	case s.HTTPAuth != nil:
		return "http/" + s.HTTPAuth.Scheme
	case s.OAuth2 != nil:
		return "oauth2"
	case s.OpenIDConnect != nil:
		return "openIdConnect"
	case s.MTLS != nil:
		return "mtls"
	default:
		return "unknown"
	}
}

// APIKeySecurityScheme - API key passed in a header, query param, or cookie.
type APIKeySecurityScheme struct {
	Description string `json:"description,omitempty"`
	Location    string `json:"location"` // required: "query" | "header" | "cookie"
	Name        string `json:"name"`     // required: parameter name e.g. "X-API-Key"
}

// HTTPAuthSecurityScheme - HTTP Authorization header (Bearer, Basic, etc.).
type HTTPAuthSecurityScheme struct {
	Description  string `json:"description,omitempty"`
	Scheme       string `json:"scheme"`                 // required: e.g. "Bearer", "Basic"
	BearerFormat string `json:"bearerFormat,omitempty"` // hint only, e.g. "JWT"
}

// OAuth2SecurityScheme describes OAuth 2.0 flows.
type OAuth2SecurityScheme struct {
	Description       string     `json:"description,omitempty"`
	Flows             OAuthFlows `json:"flows"`                       // required
	OAuth2MetadataURL string     `json:"oauth2MetadataUrl,omitempty"` // RFC 8414
}

// OAuthFlows — exactly one flow type should be populated.
type OAuthFlows struct {
	AuthorizationCode *AuthorizationCodeOAuthFlow `json:"authorizationCode,omitempty"`
	ClientCredentials *ClientCredentialsOAuthFlow `json:"clientCredentials,omitempty"`
	DeviceCode        *DeviceCodeOAuthFlow        `json:"deviceCode,omitempty"`
	Implicit          *ImplicitOAuthFlow          `json:"implicit,omitempty"` // deprecated
	Password          *PasswordOAuthFlow          `json:"password,omitempty"` // deprecated
}

// AuthorizationCodeOAuthFlow is the standard browser-based OAuth 2.0 flow.
type AuthorizationCodeOAuthFlow struct {
	AuthorizationURL string            `json:"authorizationUrl"` // required
	TokenURL         string            `json:"tokenUrl"`         // required
	RefreshURL       string            `json:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes"` // required
	PKCERequired     bool              `json:"pkceRequired,omitempty"`
}

// ClientCredentialsOAuthFlow is the machine-to-machine OAuth 2.0 flow.
type ClientCredentialsOAuthFlow struct {
	TokenURL   string            `json:"tokenUrl"` // required
	RefreshURL string            `json:"refreshUrl,omitempty"`
	Scopes     map[string]string `json:"scopes"` // required
}

// DeviceCodeOAuthFlow is the device authorization grant (RFC 8628).
type DeviceCodeOAuthFlow struct {
	DeviceAuthorizationURL string            `json:"deviceAuthorizationUrl"` // required
	TokenURL               string            `json:"tokenUrl"`               // required
	RefreshURL             string            `json:"refreshUrl,omitempty"`
	Scopes                 map[string]string `json:"scopes"` // required
}

// ImplicitOAuthFlow is deprecated per RFC 9700.
type ImplicitOAuthFlow struct {
	AuthorizationURL string            `json:"authorizationUrl"` // required
	RefreshURL       string            `json:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes"` // required
}

// PasswordOAuthFlow is deprecated per RFC 9700.
type PasswordOAuthFlow struct {
	TokenURL   string            `json:"tokenUrl"` // required
	RefreshURL string            `json:"refreshUrl,omitempty"`
	Scopes     map[string]string `json:"scopes"` // required
}

// OpenIDConnectSecurityScheme uses OIDC discovery for authentication.
type OpenIDConnectSecurityScheme struct {
	Description      string `json:"description,omitempty"`
	OpenIDConnectURL string `json:"openIdConnectUrl"` // required: OIDC discovery URL
}

// MutualTLSSecurityScheme requires mutual TLS client certificates.
type MutualTLSSecurityScheme struct {
	Description string `json:"description,omitempty"`
}

// AgentCardSignature holds a JWS signature over the Agent Card (RFC 7515).
// Used to verify the card's authenticity and detect tampering.
type AgentCardSignature struct {
	Protected string                 `json:"protected"` // required; base64url-encoded JSON header
	Signature string                 `json:"signature"` // required; base64url-encoded signature
	Header    map[string]interface{} `json:"header,omitempty"`
}
