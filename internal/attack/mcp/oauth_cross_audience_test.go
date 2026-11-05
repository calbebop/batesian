package mcp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/calbebop/batesian/internal/attack"
	mcpattack "github.com/calbebop/batesian/internal/attack/mcp"
)

func crossAudienceToken(aud, issuer string, expiry int64) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]interface{}{"iss": issuer, "aud": aud, "exp": expiry})
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

func crossAudienceOpts(targetToken, otherToken string) attack.Options {
	return attack.Options{
		TimeoutSeconds: 5, AudienceClaim: testExpectedAud, Token: targetToken,
		MCPCrossAudienceToken: otherToken,
	}
}

func crossAudienceTokens() (string, string) {
	expiry := time.Now().Add(time.Hour).Unix()
	return crossAudienceToken(testExpectedAud, "https://issuer.example", expiry),
		crossAudienceToken("https://other.example/resource", "https://issuer.example", expiry)
}

func TestCrossAudienceModern(t *testing.T) {
	targetToken, otherToken := crossAudienceTokens()
	for _, tc := range []struct {
		name        string
		acceptOther bool
		wantFinding bool
	}{
		{name: "accepted other audience", acceptOther: true, wantFinding: true},
		{name: "rejected other audience", acceptOther: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := modernAuthServer(t, func(auth string) bool {
				return auth == "Bearer "+targetToken || (tc.acceptOther && auth == "Bearer "+otherToken)
			})
			defer srv.Close()
			findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(
				context.Background(), srv.URL+"/mcp", crossAudienceOpts(targetToken, otherToken))
			if tc.wantFinding {
				if len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator ||
					!strings.Contains(findings[0].Evidence, "server/discover") {
					t.Fatalf("modern cross-audience finding=%+v, err=%v", findings, err)
				}
			} else if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("rejected other token must be inconclusive: findings=%+v, err=%v", findings, err)
			}
			if strings.Contains(errString(err), targetToken) || strings.Contains(errString(err), otherToken) {
				t.Fatal("token leaked in error")
			}
			for _, finding := range findings {
				if strings.Contains(finding.Description+finding.Evidence, targetToken) ||
					strings.Contains(finding.Description+finding.Evidence, otherToken) {
					t.Fatal("token leaked in finding")
				}
			}
		})
	}
}

func TestCrossAudienceLegacyAndSessionCleanup(t *testing.T) {
	targetToken, otherToken := crossAudienceTokens()
	var closed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodDelete {
			closed.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+targetToken &&
			r.Header.Get("Authorization") != "Bearer "+otherToken {
			challenge401(w)
			return
		}
		w.Header().Set("Mcp-Session-Id", "disposable-session")
		initializeOK(w)
	}))
	defer srv.Close()
	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(
		context.Background(), srv.URL+"/mcp", crossAudienceOpts(targetToken, otherToken))
	if len(findings) != 1 || findings[0].Confidence != attack.RiskIndicator ||
		!strings.Contains(findings[0].Evidence, "initialize") {
		t.Fatalf("legacy cross-audience finding=%+v, err=%v", findings, err)
	}
	if got := closed.Load(); got < 2 {
		t.Fatalf("legacy sessions not closed: %d DELETE requests", got)
	}
}

func TestCrossAudienceRequiresAnonymousDenial(t *testing.T) {
	targetToken, otherToken := crossAudienceTokens()
	srv := modernAuthServer(t, func(string) bool { return true })
	defer srv.Close()
	findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(
		context.Background(), srv.URL+"/mcp", crossAudienceOpts(targetToken, otherToken))
	if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
		t.Fatalf("open method cannot establish audience bypass: findings=%+v, err=%v", findings, err)
	}
}

func TestCrossAudienceRequiresDistinctValidClaims(t *testing.T) {
	targetToken, _ := crossAudienceTokens()
	for _, tc := range []struct {
		name  string
		token string
	}{
		{name: "same token", token: targetToken},
		{name: "opaque token", token: "opaque"},
		{name: "expired token", token: crossAudienceToken("https://other.example/resource", "https://issuer.example", time.Now().Add(-time.Minute).Unix())},
		{name: "wrong issuer", token: crossAudienceToken("https://other.example/resource", "https://different.example", time.Now().Add(time.Hour).Unix())},
		{name: "target audience included", token: crossAudienceToken(testExpectedAud, "https://issuer.example", time.Now().Add(2*time.Hour).Unix())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var otherTokenRequests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer "+tc.token {
					otherTokenRequests.Add(1)
				}
				challenge401(w)
			}))
			defer srv.Close()
			findings, err := mcpattack.NewOAuthAudienceExecutor(oauthAudienceRC()).Execute(
				context.Background(), srv.URL+"/mcp", crossAudienceOpts(targetToken, tc.token))
			if len(findings) != 0 || !errors.Is(err, attack.ErrInconclusive) {
				t.Fatalf("invalid comparison accepted: findings=%+v, err=%v", findings, err)
			}
			if tc.name != "same token" && otherTokenRequests.Load() != 0 {
				t.Fatalf("invalid other token was sent %d times", otherTokenRequests.Load())
			}
		})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
