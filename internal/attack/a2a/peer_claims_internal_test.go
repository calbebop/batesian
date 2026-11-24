package a2a

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestDeriveForgedClaims_IgnoresNonOKResourceMetadata(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-protected-resource/a2a" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"resource": srv.URL + "/a2a", "authorization_servers": []string{"https://issuer.example.test"},
		})
	}))
	defer srv.Close()

	target := srv.URL + "/a2a"
	client := attack.NewUnauthHTTPClient(attack.Options{}, attack.NewVars(target, ""))
	claims := deriveForgedClaims(t.Context(), client, target, target, target, nil)
	if claims.iss != fallbackForgedIssuer || claims.issuerReliable {
		t.Fatalf("non-200 resource metadata supplied issuer: %+v", claims)
	}
}
