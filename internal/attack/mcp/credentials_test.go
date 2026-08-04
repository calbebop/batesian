package mcp

import "testing"

// matchesAnyCredentialPattern mirrors what the rule does with a resource body.
func matchesAnyCredentialPattern(s string) bool {
	for _, re := range credentialPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// Credentials carried positionally in a URI userinfo section are a routine way
// for a resource to leak a secret, and the password pattern cannot see one: it
// looks for password=value, not scheme://user:secret@host. A false negative
// here costs a critical finding, since the rule escalates on nothing else.
func TestCredentialPatterns_URIUserinfo(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "postgres connection string",
			input: "postgresql://admin:password123@db.internal:5432/prod",
			want:  true,
		},
		{
			name:  "database url assignment",
			input: "DATABASE_URL=postgresql://admin:hunter2@db.internal/prod",
			want:  true,
		},
		{
			name:  "mongodb srv",
			input: "mongodb+srv://svc:s3cr3t@cluster0.example.net/app",
			want:  true,
		},
		{
			// Some clients pass the secret with an empty username.
			name:  "redis with no username",
			input: "redis://:mypassword@cache.internal:6379/0",
			want:  true,
		},
		{
			name:  "https basic auth in url",
			input: "https://svc-account:tokenvalue@api.example.com/v1",
			want:  true,
		},
		{
			// The common shape that must NOT match: a port is a colon too, and
			// treating one as a password would fire on almost any URL.
			name:  "ordinary url with a port",
			input: "http://db.internal:5432/prod",
			want:  false,
		},
		{
			name:  "url with a port and a path that has an at sign",
			input: "https://example.com:8443/users/me@example.com",
			want:  false,
		},
		{
			// A username with no password is not a secret.
			name:  "userinfo without a password",
			input: "https://someuser@github.com/org/repo.git",
			want:  false,
		},
		{
			name:  "bare email address",
			input: "contact: support@example.com",
			want:  false,
		},
		{
			name:  "plain prose",
			input: "Welcome to the public configuration overview page.",
			want:  false,
		},
		{
			name:  "json config with no secret",
			input: `{"debug": false, "log_level": "info", "allowed_origins": ["https://app.example.com"]}`,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesAnyCredentialPattern(tt.input); got != tt.want {
				t.Errorf("matchesAnyCredentialPattern(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// The patterns that were already here keep working; this guards against a later
// edit to the URI pattern accidentally reordering or replacing one of them.
func TestCredentialPatterns_ExistingShapesStillMatch(t *testing.T) {
	for _, s := range []string{
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"API_KEY=SG.test_api_key_value_here",
		"password: supersecret",
		"-----BEGIN RSA PRIVATE KEY-----",
		"Authorization=abcdefghijklmnopqrst",
	} {
		if !matchesAnyCredentialPattern(s) {
			t.Errorf("expected a credential match for %q", s)
		}
	}
}

// The canonical header form is what an operator is most likely to find in a
// leaked config, and it used to be the one shape the bearer pattern could not
// see: after "authorization:" the next token is "Bearer", six characters, which
// failed the \S{10,} the pattern needs.
func TestCredentialPatterns_AuthorizationHeader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "canonical header form",
			input: "Authorization: Bearer sk_live_51H8xQ2eZvKYlo2C",
			want:  true,
		},
		{
			name:  "lowercase header",
			input: "authorization: bearer abcdefghijklmnop",
			want:  true,
		},
		{
			name:  "yaml style with quotes",
			input: `authorization: "Bearer ghp_abcdefghijklmnopqrst"`,
			want:  true,
		},
		{
			// Content is matched against the raw JSON-RPC body, so a quote
			// inside a resource arrives escaped.
			name:  "json escaped quote before the value",
			input: `{"text":"authorization: \"Bearer ghp_abcdefghijklmnopqrst\""}`,
			want:  true,
		},
		{
			name:  "no bearer prefix, token directly after the separator",
			input: "Authorization=abcdefghijklmnopqrst",
			want:  true,
		},
		{
			// Making the separator optional to catch a bare "Bearer <token>"
			// would match this, so the separator stays required.
			name:  "prose about authorization",
			input: "Authorization requirements documented in the handbook",
			want:  false,
		},
		{
			name:  "header naming a scheme but no token",
			input: "Authorization: required",
			want:  false,
		},
		{
			name:  "bearer prefix with too short a token",
			input: "Authorization: Bearer short",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesAnyCredentialPattern(tt.input); got != tt.want {
				t.Errorf("matchesAnyCredentialPattern(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// Deliberate boundary: a standalone "Bearer <token>" with no Authorization
// keyword and no separator still does not match, because keying on a bare
// "bearer" would fire on prose. The common case is covered anyway, since a JWT
// matches the eyJ pattern whatever precedes it.
func TestCredentialPatterns_StandaloneBearerBoundary(t *testing.T) {
	if matchesAnyCredentialPattern("bearer instruments outstanding at year end") {
		t.Error("a bare bearer keyword in prose must not match")
	}
	if !matchesAnyCredentialPattern("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9") {
		t.Error("a bearer-prefixed JWT should still match, via the JWT pattern")
	}
}
