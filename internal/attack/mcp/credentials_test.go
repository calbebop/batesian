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

// Known gap, deliberately not asserted either way so that fixing it does not
// have to fight a test: the bearer pattern is
// (bearer|authorization)\s*[=:]\s*\S{10,}, which cannot match the canonical
// header form "Authorization: Bearer <token>". After "authorization:" the next
// token is "Bearer", only six characters, and after "bearer" there is no
// separator at all. So the one shape an operator is most likely to find in a
// leaked config is the one shape this does not catch. Left alone here because
// it is a separate change from the URI userinfo gap this file was added for.
