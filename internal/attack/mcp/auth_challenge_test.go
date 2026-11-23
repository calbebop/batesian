package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestAuthChallenges(t *testing.T) {
	for _, tc := range []struct {
		name        string
		values      []string
		bearer      bool
		metadataURL string
	}{
		{
			name:   "combined challenges and parameters",
			values: []string{`Basic realm="staff,Bearer", bEaReR realm="mcp", resource_metadata="https://resource.example/prm"`},
			bearer: true, metadataURL: "https://resource.example/prm",
		},
		{
			name:   "separate fields with DPoP metadata",
			values: []string{`Basic realm="staff"`, `DPoP resource_metadata="https://resource.example/prm"`, `Bearer realm="mcp"`},
			bearer: true, metadataURL: "https://resource.example/prm",
		},
		{
			name:   "quoted bait",
			values: []string{`Basic realm="Bearer resource_metadata=\"https://bait.example/prm\""`},
		},
		{
			name:        "scheme prefix",
			values:      []string{`Bearerish resource_metadata="https://resource.example/prm"`},
			metadataURL: "https://resource.example/prm",
		},
		{
			name:   "invalid metadata parameter",
			values: []string{`Bearer resource_metadata=https://resource.example/prm`},
			bearer: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)
			for _, value := range tc.values {
				headers.Add("WWW-Authenticate", value)
			}
			if got := hasBearerChallenge(&attack.Response{Headers: headers}); got != tc.bearer {
				t.Errorf("Bearer challenge = %t, want %t", got, tc.bearer)
			}
			if got := parseResourceMetadataURL(headers); got != tc.metadataURL {
				t.Errorf("resource metadata = %q, want %q", got, tc.metadataURL)
			}
		})
	}
}

func TestAuthChallengesInProbes(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("WWW-Authenticate", `Basic realm="staff"`)
		w.Header().Add("WWW-Authenticate", `Bearer realm="mcp"`)
		w.Header().Add("WWW-Authenticate", `DPoP resource_metadata="`+srv.URL+`/prm"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	vars := attack.NewVars(srv.URL+"/mcp", "")
	client := attack.NewUnauthHTTPClient(attack.Options{TimeoutSeconds: 5}, vars)
	gate := probeModernAuthGate(t.Context(), client, vars.BaseURL)
	if !gate.ready || gate.method != "server/discover" {
		t.Errorf("modern gate = %+v, want challenged discovery", gate)
	}
	metadataURL, _, reached, _ := probeWWWAuthenticateResourceMetadata(t.Context(), client, vars.BaseURL)
	if !reached || metadataURL != srv.URL+"/prm" {
		t.Errorf("OAuth challenge = %q, reached = %t", metadataURL, reached)
	}
}
