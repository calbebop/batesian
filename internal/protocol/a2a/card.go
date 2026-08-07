// Package a2a provides types and a client for the Agent-to-Agent (A2A) protocol.
// Spec reference: https://a2a-protocol.org/latest/specification/
package a2a

import (
	"encoding/json"
	"net/url"
	"strings"
)

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
	// Order is not significant: the JSON-RPC interface is selected by binding, not
	// by position (the first entry is frequently gRPC).
	SupportedInterfaces []AgentInterface `json:"supportedInterfaces,omitempty"`

	// AdditionalInterfaces lists alternate-transport endpoints in v0.3 cards, each
	// tagged with a transport rather than a protocolBinding.
	AdditionalInterfaces []AgentInterface `json:"additionalInterfaces,omitempty"`

	// PreferredTransport names the transport for the top-level URL in v0.3 cards
	// (e.g. "JSONRPC", "GRPC").
	PreferredTransport string `json:"preferredTransport,omitempty"`

	// URL is the v0.3 top-level service URL field. Still present in many deployed
	// agents; usable as the JSON-RPC endpoint only when PreferredTransport is JSONRPC.
	URL string `json:"url,omitempty"`

	// Required content-type defaults
	DefaultInputModes  []string `json:"defaultInputModes,omitempty"`
	DefaultOutputModes []string `json:"defaultOutputModes,omitempty"`

	// Optional metadata
	DocumentationURL string         `json:"documentationUrl,omitempty"`
	Provider         *AgentProvider `json:"provider,omitempty"`
	IconURL          string         `json:"iconUrl,omitempty"`

	// Authentication (OpenAPI-style security schemes). The requirements list is
	// named securityRequirements in v1.0 (proto JSON) but security in v0.3 cards;
	// both are captured so either version's declared auth can be read.
	SecuritySchemes      map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	SecurityRequirements []SecurityRequirement     `json:"securityRequirements,omitempty"`
	Security             []SecurityRequirement     `json:"security,omitempty"`

	// Signatures holds JWS signatures over the Agent Card (RFC 7515).
	Signatures []AgentCardSignature `json:"signatures,omitempty"`
}

// GetServiceURL returns the agent's JSON-RPC service URL, the transport batesian
// speaks. It selects by binding rather than by position, because the first
// supportedInterfaces entry is frequently gRPC (whose URL is often scheme-less).
// Preference order: a v1.0 JSON-RPC interface, then a v0.3 additionalInterfaces
// JSON-RPC entry, then the top-level url when preferredTransport is JSONRPC.
// Failing that it returns the first http(s) interface, then the legacy url.
func (c *AgentCard) GetServiceURL() string {
	for _, i := range c.SupportedInterfaces {
		if strings.EqualFold(i.ProtocolBinding, "JSONRPC") && hasHTTPScheme(i.URL) {
			return i.URL
		}
	}
	for _, i := range c.AdditionalInterfaces {
		if strings.EqualFold(i.Transport, "JSONRPC") && hasHTTPScheme(i.URL) {
			return i.URL
		}
	}
	if strings.EqualFold(c.PreferredTransport, "JSONRPC") && c.URL != "" {
		return c.URL
	}
	// No JSON-RPC interface advertised; fall back to a usable URL for display.
	for _, i := range c.SupportedInterfaces {
		if hasHTTPScheme(i.URL) {
			return i.URL
		}
	}
	return c.URL
}

// hasHTTPScheme reports whether rawURL is an absolute http(s) URL. gRPC interface
// URLs are typically scheme-less "host:port" and are not usable for JSON-RPC.
func hasHTTPScheme(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// AgentInterface describes a single A2A service endpoint. v1.0 cards tag the
// transport with protocolBinding; v0.3 additionalInterfaces use transport.
type AgentInterface struct {
	URL             string `json:"url"`                       // required; absolute URL (http(s) for JSON-RPC)
	ProtocolBinding string `json:"protocolBinding,omitempty"` // v1.0; "JSONRPC" | "GRPC" | "HTTP+JSON"
	Transport       string `json:"transport,omitempty"`       // v0.3; same vocabulary as protocolBinding
	ProtocolVersion string `json:"protocolVersion,omitempty"`
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

// DeclaredSecurity returns the requirements list the card actually declares,
// preferring the v1.0 securityRequirements field and falling back to the v0.3
// security field.
//
// The two spellings hold the same statement, so a caller asking "what auth does
// this card require" must consult both. Reading only securityRequirements
// reported every v0.3 agent as unauthenticated, including ones that reject
// anonymous callers outright. The precedence lives here so callers do not each
// reimplement it.
func (c *AgentCard) DeclaredSecurity() []SecurityRequirement {
	if len(c.SecurityRequirements) > 0 {
		return c.SecurityRequirements
	}
	return c.Security
}

// RequiresAuth reports whether the card declares authentication with no
// anonymous alternative. Per OpenAPI semantics an empty requirement object in the
// list explicitly permits anonymous access, so its presence means auth is not
// required whatever else the list holds.
func (c *AgentCard) RequiresAuth() bool {
	list := c.DeclaredSecurity()
	if len(list) == 0 {
		return false
	}
	for _, req := range list {
		if len(req) == 0 {
			return false
		}
	}
	return true
}

// SecurityRequirement maps scheme names to required OAuth scopes.
// An empty slice means the scheme is required but no specific scopes are needed.
type SecurityRequirement map[string][]string

// UnmarshalJSON accepts both wire shapes a requirement entry appears in.
//
// v1.0 is proto-derived: SecurityRequirement is a message holding a single map
// field named schemes, whose values are StringList messages, so an entry
// serializes with the names one level down:
//
//	{"schemes": {"bearerAuth": {"list": ["a2a:invoke"]}}}
//
// v0.3 and OpenAPI put the names at the top level with scope arrays as values:
//
//	{"bearerAuth": ["a2a:invoke"]}
//
// Both official SDKs emit the first. Decoding straight into map[string][]string
// accepted only the second, so json.Unmarshal failed on every real v1.0 card
// that declared security, and because FetchAgentCard treats an unmarshal error
// as fatal, probe reported those agents as not serving valid JSON. Agents that
// declared nothing probed fine, so the failure landed only on the ones
// configured correctly.
//
// The two are told apart by structure, not by which card field they came from: an
// entry whose sole key is "schemes" mapping to an object is the proto shape. A
// v0.3 card may declare a scheme actually named "schemes", but then its value is
// a scope array rather than an object, so that card still reads correctly.
//
// A value that is neither a scope array nor a StringList map records the scheme
// name with no scopes rather than failing. Refusing to decode would sink the
// whole card over one optional field, which is the bug this method exists to
// fix; a recon parser should show the operator what is there.
func (s *SecurityRequirement) UnmarshalJSON(data []byte) error {
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(data, &entry); err != nil {
		// Not an object at all. Leave the requirement empty rather than failing
		// the card: an entry that names no scheme requires nothing, which is
		// also what an empty object means.
		*s = SecurityRequirement{}
		return nil
	}

	if inner, ok := protoSchemeMap(entry); ok {
		*s = inner
		return nil
	}

	out := make(SecurityRequirement, len(entry))
	for name, raw := range entry {
		var scopes []string
		if err := json.Unmarshal(raw, &scopes); err != nil {
			scopes = nil
		}
		out[name] = scopes
	}
	*s = out
	return nil
}

// protoSchemeMap reads the v1.0 nested shape, returning ok false when entry is
// not that shape and should be read as a flat OpenAPI-style requirement.
func protoSchemeMap(entry map[string]json.RawMessage) (SecurityRequirement, bool) {
	if len(entry) != 1 {
		return nil, false
	}
	raw, present := entry["schemes"]
	if !present {
		return nil, false
	}
	var schemes map[string]struct {
		List []string `json:"list"`
	}
	if err := json.Unmarshal(raw, &schemes); err != nil {
		return nil, false
	}
	out := make(SecurityRequirement, len(schemes))
	for name, list := range schemes {
		out[name] = list.List
	}
	return out, true
}

// SecurityScheme is a discriminated union - exactly one nested scheme object is populated.
// In v1.0 the discriminant is the JSON key name itself (apiKeySecurityScheme,
// httpAuthSecurityScheme, etc.). v0.3 cards instead use the OpenAPI form, a flat
// object carrying a "type" field; UnmarshalJSON reads both into these fields.
type SecurityScheme struct {
	APIKey        *APIKeySecurityScheme        `json:"apiKeySecurityScheme,omitempty"`
	HTTPAuth      *HTTPAuthSecurityScheme      `json:"httpAuthSecurityScheme,omitempty"`
	OAuth2        *OAuth2SecurityScheme        `json:"oauth2SecurityScheme,omitempty"`
	OpenIDConnect *OpenIDConnectSecurityScheme `json:"openIdConnectSecurityScheme,omitempty"`
	MTLS          *MutualTLSSecurityScheme     `json:"mtlsSecurityScheme,omitempty"`
}

// UnmarshalJSON accepts the v1.0 nested form and the v0.3 OpenAPI flat form.
//
// v1.0 keys the union on the member name:
//
//	{"httpAuthSecurityScheme": {"scheme": "bearer"}}
//
// v0.3 follows OpenAPI, with a flat object and a "type" discriminant. The shapes
// served by the official Go SDK, which is a native v0.3 implementation, are:
//
//	{"type": "http",          "scheme": "bearer", "bearerFormat": "opaque"}
//	{"type": "apiKey",        "in": "header", "name": "X-API-Key"}
//	{"type": "oauth2",        "flows": {...}}
//	{"type": "openIdConnect", "openIdConnectUrl": "..."}
//	{"type": "mutualTLS"}
//
// Without this, a v0.3 card left every member nil and Type() reported "unknown",
// so probe could not name the scheme an agent declared. Note apiKey carries the
// location under "in" here and under "location" in v1.0, so both are read.
func (s *SecurityScheme) UnmarshalJSON(data []byte) error {
	// The nested form first: it is unambiguous, since none of its keys collide
	// with the flat form's.
	type nested SecurityScheme
	var n nested
	if err := json.Unmarshal(data, &n); err == nil {
		candidate := SecurityScheme(n)
		if candidate.Type() != "unknown" {
			*s = candidate
			return nil
		}
	}

	var flat struct {
		Type              string            `json:"type"`
		Description       string            `json:"description"`
		Scheme            string            `json:"scheme"`
		BearerFormat      string            `json:"bearerFormat"`
		In                string            `json:"in"`
		Location          string            `json:"location"`
		Name              string            `json:"name"`
		Flows             OAuthFlows        `json:"flows"`
		OAuth2MetadataURL string            `json:"oauth2MetadataUrl"`
		OpenIDConnectURL  string            `json:"openIdConnectUrl"`
		Scopes            map[string]string `json:"scopes"`
	}
	if err := json.Unmarshal(data, &flat); err != nil {
		// Not an object we can read. Leave the scheme empty rather than failing
		// the card: Type() reports "unknown", which is the honest answer, and one
		// unreadable scheme must not cost the operator the whole card.
		*s = SecurityScheme{}
		return nil
	}

	switch flat.Type {
	case "http":
		s.HTTPAuth = &HTTPAuthSecurityScheme{
			Description: flat.Description, Scheme: flat.Scheme, BearerFormat: flat.BearerFormat,
		}
	case "apiKey":
		location := flat.In
		if location == "" {
			location = flat.Location
		}
		s.APIKey = &APIKeySecurityScheme{
			Description: flat.Description, Location: location, Name: flat.Name,
		}
	case "oauth2":
		s.OAuth2 = &OAuth2SecurityScheme{
			Description: flat.Description, Flows: flat.Flows, OAuth2MetadataURL: flat.OAuth2MetadataURL,
		}
	case "openIdConnect":
		s.OpenIDConnect = &OpenIDConnectSecurityScheme{
			Description: flat.Description, OpenIDConnectURL: flat.OpenIDConnectURL,
		}
	case "mutualTLS":
		s.MTLS = &MutualTLSSecurityScheme{Description: flat.Description}
	}
	return nil
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

// OAuthFlows - exactly one flow type should be populated.
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
