package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/config"
	"github.com/calbebop/batesian/internal/rules"
)

func TestParsePrincipalFlag_Valid(t *testing.T) {
	p, err := parsePrincipalFlag("name=tenant-a,token=eyJabc,tenant=A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name != "tenant-a" || p.Token != "eyJabc" || p.Tenant != "A" {
		t.Errorf("parsed principal mismatch: %+v", p)
	}
}

func TestParsePrincipalFlag_MissingName(t *testing.T) {
	if _, err := parsePrincipalFlag("token=abc,tenant=A"); err == nil {
		t.Error("expected error when name= is absent, got nil")
	}
}

func TestParsePrincipalFlag_UnknownKey(t *testing.T) {
	if _, err := parsePrincipalFlag("name=a,role=admin"); err == nil {
		t.Error("expected error for unknown key, got nil")
	}
}

func TestParsePrincipalFlag_InvalidSegment(t *testing.T) {
	if _, err := parsePrincipalFlag("name=a,justakey"); err == nil {
		t.Error("expected error for key without =, got nil")
	}
}

// Five multi-principal A2A rules send Principal.Headers. Multi-tenant deployments
// commonly resolve the tenant at a gateway and pass it downstream in a header, so a
// flag that cannot express one cannot describe the identities it is comparing.
// Against a header-scoped agent that isolates correctly, the headerless form
// produced two false-positive cross-tenant findings.
func TestParsePrincipalFlag_HeadersAreRepeatable(t *testing.T) {
	p, err := parsePrincipalFlag("name=a,token=t,tenant=A,header=X-Tenant-Id:A,header=X-Env:prod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Headers) != 2 {
		t.Fatalf("expected both headers, got %+v", p.Headers)
	}
	if p.Headers["X-Tenant-Id"] != "A" || p.Headers["X-Env"] != "prod" {
		t.Errorf("header values mismatch: %+v", p.Headers)
	}
	// The other fields must still parse alongside.
	if p.Name != "a" || p.Token != "t" || p.Tenant != "A" {
		t.Errorf("non-header fields mismatch: %+v", p)
	}
}

// A header value may itself contain colons, e.g. a URL, so only the first splits.
func TestParsePrincipalFlag_HeaderValueKeepsLaterColons(t *testing.T) {
	p, err := parsePrincipalFlag("name=a,header=X-Origin:https://tenant-a.example.test:8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := p.Headers["X-Origin"]; got != "https://tenant-a.example.test:8443" {
		t.Errorf("value should keep everything after the first colon, got %q", got)
	}
}

func TestParsePrincipalFlag_HeaderNeedsNameAndValue(t *testing.T) {
	for _, bad := range []string{"name=a,header=NoColon", "name=a,header=:justvalue"} {
		if _, err := parsePrincipalFlag(bad); err == nil {
			t.Errorf("expected an error for %q, got nil", bad)
		}
	}
}

// The config file spells this as a `headers:` map, so it is the first thing an
// operator reaches for here. The error has to point at the form that works.
func TestParsePrincipalFlag_PluralHeadersIsGuided(t *testing.T) {
	_, err := parsePrincipalFlag("name=a,headers=X-Tenant-Id:A")
	if err == nil {
		t.Fatal("expected an error for headers=, got nil")
	}
	if !strings.Contains(err.Error(), "header=Name:Value") {
		t.Errorf("error should name the working form, got: %v", err)
	}
}

func TestBuildPrincipals_MergesConfigThenFlags(t *testing.T) {
	cfgPrincipals := []config.PrincipalConfig{
		{Name: "tenant-a", Token: "token-a", Tenant: "A"},
	}
	flags := []string{"name=tenant-b,token=token-b,tenant=B"}

	got, err := buildPrincipals(cfgPrincipals, flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 principals, got %d", len(got))
	}
	if got[0].Name != "tenant-a" || got[1].Name != "tenant-b" {
		t.Errorf("merge order wrong (config first, flags appended): %+v", got)
	}
}

func TestBuildPrincipals_ResolvesConfigTokenEnvironment(t *testing.T) {
	t.Setenv("BATESIAN_TOKEN_A", "principal-secret")
	got, err := buildPrincipals([]config.PrincipalConfig{
		{Name: "tenant-a", Token: "${BATESIAN_TOKEN_A}"},
		{Name: "tenant-b", Token: "literal-token"},
	}, nil)
	if err != nil {
		t.Fatalf("building principals: %v", err)
	}
	if got[0].Token != "principal-secret" || got[1].Token != "literal-token" {
		t.Fatal("config token references were not resolved")
	}
}

func TestBuildPrincipals_RejectsUnavailableConfigToken(t *testing.T) {
	t.Setenv("BATESIAN_TOKEN_A", "")
	_, err := buildPrincipals([]config.PrincipalConfig{{Name: "tenant-a", Token: "${BATESIAN_TOKEN_A}"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "BATESIAN_TOKEN_A") {
		t.Fatalf("error = %v, want missing environment variable name", err)
	}
}

func TestBuildPrincipals_RejectsMalformedConfigTokenReference(t *testing.T) {
	_, err := buildPrincipals([]config.PrincipalConfig{{Name: "tenant-a", Token: "${BATESIAN_TOKEN_A"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid token environment reference") {
		t.Fatalf("error = %v, want malformed reference error", err)
	}
}

func TestBuildPrincipals_DuplicateAcrossSources(t *testing.T) {
	cfgPrincipals := []config.PrincipalConfig{{Name: "dup", Token: "x"}}
	flags := []string{"name=dup,token=y"}
	if _, err := buildPrincipals(cfgPrincipals, flags); err == nil {
		t.Error("expected duplicate-name error across config + flags, got nil")
	}
}

func TestBuildPrincipals_Empty(t *testing.T) {
	got, err := buildPrincipals(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no principals, got %d", len(got))
	}
}

func TestBuildExpectedDenials(t *testing.T) {
	principals := []attack.Principal{{Name: "tenant-a", Tenant: "A"}, {Name: "tenant-b", Tenant: "B"}}
	entry := config.ExpectedDenialConfig{Operation: attack.A2ATasksCancel, Caller: "tenant-b", CallerTenant: "B", Owner: "tenant-a", OwnerTenant: "A"}
	got, err := buildExpectedDenials([]config.ExpectedDenialConfig{entry}, principals)
	if err != nil || len(got) != 1 || got[0].Caller != "tenant-b" || got[0].Owner != "tenant-a" {
		t.Fatalf("denials = %+v, error = %v", got, err)
	}
	entry.Operation = attack.MCPTasksGet
	got, err = buildExpectedDenials([]config.ExpectedDenialConfig{entry}, principals)
	if err != nil || len(got) != 1 || got[0].Operation != attack.MCPTasksGet {
		t.Fatalf("MCP task denials = %+v, error = %v", got, err)
	}
	for _, tt := range []struct {
		name  string
		entry config.ExpectedDenialConfig
		want  string
	}{
		{"unknown caller", config.ExpectedDenialConfig{Operation: attack.A2ATasksCancel, Caller: "missing", Owner: "tenant-a"}, "unknown caller principal"},
		{"unknown owner", config.ExpectedDenialConfig{Operation: attack.A2ATasksCancel, Caller: "tenant-b", Owner: "missing"}, "unknown owner principal"},
		{"wrong caller tenant", config.ExpectedDenialConfig{Operation: attack.A2ATasksCancel, Caller: "tenant-b", CallerTenant: "A", Owner: "tenant-a"}, "caller_tenant does not match"},
		{"wrong owner tenant", config.ExpectedDenialConfig{Operation: attack.A2ATasksCancel, Caller: "tenant-b", Owner: "tenant-a", OwnerTenant: "B"}, "owner_tenant does not match"},
		{"MCP task unknown owner", config.ExpectedDenialConfig{Operation: attack.MCPTasksCancel, Caller: "tenant-b", Owner: "missing"}, "unknown owner principal"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildExpectedDenials([]config.ExpectedDenialConfig{tt.entry}, principals)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestScanExpectedDenialsRejectDifferentTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batesian.yaml")
	content := "target: https://agent.example.com\nexpected_denials:\n  - operation: mcp.prompts.get\n    caller: anonymous\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", path)
	setScanFlag(t, "target", "https://other.example.com")
	if err := runScan(scanCmd, nil); err == nil || !strings.Contains(err.Error(), "cannot be used with a different --target") {
		t.Fatalf("error = %v, want policy target mismatch", err)
	}
}

func TestEffectiveTimeout(t *testing.T) {
	tests := []struct {
		name        string
		flagChanged bool
		flagVal     int
		cfgVal      int
		want        int
	}{
		// The bug this guards: an explicit --timeout 10 (equal to the default)
		// must not be overridden by a config value.
		{"explicit flag equal to default wins over config", true, 10, 30, 10},
		{"explicit flag wins even when config is zero", true, 25, 0, 25},
		{"config used when flag not set", false, 10, 30, 30},
		{"flag default when neither set", false, 10, 0, 10},
		{"negative config preserved for validation", false, 10, -5, -5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveTimeout(tc.flagChanged, tc.flagVal, tc.cfgVal); got != tc.want {
				t.Errorf("effectiveTimeout(%v, %d, %d) = %d, want %d", tc.flagChanged, tc.flagVal, tc.cfgVal, got, tc.want)
			}
		})
	}
}

func TestEffectiveSkipTLS(t *testing.T) {
	tests := []struct {
		name        string
		flagChanged bool
		flagVal     bool
		cfgVal      bool
		want        bool
	}{
		// The bug this guards: an explicit --skip-tls=false must override a config
		// that sets skipTLS: true.
		{"explicit false overrides config true", true, false, true, false},
		{"explicit true used", true, true, false, true},
		{"config used when flag not set", false, false, true, true},
		{"both unset", false, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveSkipTLS(tc.flagChanged, tc.flagVal, tc.cfgVal); got != tc.want {
				t.Errorf("effectiveSkipTLS(%v, %v, %v) = %v, want %v", tc.flagChanged, tc.flagVal, tc.cfgVal, got, tc.want)
			}
		})
	}
}

func TestEffectiveOutput(t *testing.T) {
	tests := []struct {
		name        string
		flagChanged bool
		flagVal     string
		cfgVal      string
		want        string
	}{
		// The bug this guards: the flag carries a default, so the old
		// empty-string sentinel never fired and the config value could never
		// apply. "flag wins" therefore means "flag was actually passed".
		{"explicit flag wins over config", true, "json", "sarif", "json"},
		{"explicit flag equal to default wins over config", true, "table", "sarif", "table"},
		{"config used when flag not passed", false, "table", "sarif", "sarif"},
		{"flag default when neither set", false, "table", "", "table"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveOutput(tc.flagChanged, tc.flagVal, tc.cfgVal); got != tc.want {
				t.Errorf("effectiveOutput(%v, %q, %q) = %q, want %q", tc.flagChanged, tc.flagVal, tc.cfgVal, got, tc.want)
			}
		})
	}
}

func TestEffectiveOAuthOrigins(t *testing.T) {
	configured := []string{"https://login.example.com"}
	tests := []struct {
		name        string
		flagChanged bool
		flagValue   []string
		want        []string
	}{
		{"config used when flag not passed", false, nil, configured},
		{"flag replaces config", true, []string{"https://other.example.com"}, []string{"https://other.example.com"}},
		{"explicit empty flag clears config", true, []string{}, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveOAuthOrigins(tc.flagChanged, tc.flagValue, configured)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEffectiveMCPScopeTools(t *testing.T) {
	configured := []string{"delete_item"}
	tests := []struct {
		name        string
		flagChanged bool
		flagValue   []string
		want        []string
	}{
		{"config used by default", false, nil, configured},
		{"flag replaces config", true, []string{"send_email"}, []string{"send_email"}},
		{"empty flag clears config", true, []string{}, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveMCPScopeTools(tc.flagChanged, tc.flagValue, configured)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEffectiveMCPInvokeTools(t *testing.T) {
	configured := []string{"read_note"}
	tests := []struct {
		name        string
		flagChanged bool
		flagValue   []string
		want        []string
	}{
		{"config used by default", false, nil, configured},
		{"flag replaces config", true, []string{"wait_a_moment"}, []string{"wait_a_moment"}},
		{"empty flag clears config", true, []string{}, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveMCPInvokeTools(tc.flagChanged, tc.flagValue, configured)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateOAuthAcquisition(t *testing.T) {
	const (
		credentialsError = "OAuth token acquisition requires --client-id and --token-url"
		pkceError        = "--auth-url requires --client-id and --token-url for the PKCE flow"
	)
	tests := []struct {
		name                                               string
		token, authURL, tokenURL, issuer, clientID, secret string
		scopes                                             []string
		audience, want                                     string
	}{
		{name: "unset"},
		{name: "client credentials", tokenURL: "https://auth.example/token", clientID: "client"},
		{name: "client credentials options", tokenURL: "https://auth.example/token", clientID: "client", secret: "secret", scopes: []string{"mcp:read"}, audience: "mcp"},
		{name: "PKCE", authURL: "https://auth.example/authorize", tokenURL: "https://auth.example/token", clientID: "client"},
		{name: "PKCE with issuer", authURL: "https://auth.example/authorize", tokenURL: "https://auth.example/token", issuer: "https://auth.example", clientID: "client"},
		{name: "issuer without PKCE", issuer: "https://auth.example", want: "--oauth-issuer requires --auth-url for the PKCE flow"},
		{name: "token URL only", tokenURL: "https://auth.example/token", want: credentialsError},
		{name: "client ID only", clientID: "client", want: credentialsError},
		{name: "client secret only", secret: "secret", want: credentialsError},
		{name: "scopes only", scopes: []string{"mcp:read"}, want: credentialsError},
		{name: "audience only", audience: "mcp", want: credentialsError},
		{name: "PKCE missing client ID", authURL: "https://auth.example/authorize", tokenURL: "https://auth.example/token", want: pkceError},
		{name: "PKCE missing token URL", authURL: "https://auth.example/authorize", clientID: "client", want: pkceError},
		{name: "bearer token takes precedence", token: "bearer", authURL: "https://auth.example/authorize"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOAuthAcquisition(tc.token, tc.authURL, tc.tokenURL, tc.issuer, tc.clientID, tc.secret, tc.scopes, tc.audience)
			if tc.want == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.want != "" && (err == nil || err.Error() != tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestScanClientSecretEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, flag, want string
	}{
		{"environment", "", "env-secret"},
		{"flag overrides environment", "flag-secret", "flag-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BATESIAN_TOKEN", "")
			t.Setenv("BATESIAN_CLIENT_SECRET", "env-secret")
			received := make(chan string, 1)
			oauth := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Errorf("parsing token request: %v", err)
				}
				received <- r.Form.Get("client_secret")
				w.WriteHeader(http.StatusBadRequest)
			}))
			defer oauth.Close()

			if scanCmd.Flags().Lookup("target") == nil {
				scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
			}
			setScanFlag(t, "no-config", "true")
			setScanFlag(t, "target", "https://agent.example.com")
			setScanFlag(t, "protocol", "a2a")
			setScanSliceFlag(t, "rule-ids", []string{"a2a-card-trust-001"})
			setScanFlag(t, "token", "")
			setScanFlag(t, "auth-url", "")
			setScanFlag(t, "token-url", oauth.URL)
			setScanFlag(t, "client-id", "client")
			setScanFlag(t, "client-secret", tc.flag)
			setScanFlag(t, "skip-tls", "true")
			setScanFlag(t, "dry-run", "false")
			scanCmd.SetContext(context.Background())

			err := runScan(scanCmd, nil)
			if err == nil || !strings.Contains(err.Error(), "token endpoint returned HTTP 400") {
				t.Fatalf("expected token request rejection, got %v", err)
			}
			select {
			case got := <-received:
				if got != tc.want {
					t.Fatalf("client_secret = %q, want %q", got, tc.want)
				}
			default:
				t.Fatal("token endpoint was not called")
			}
		})
	}
}

func TestScan_DryRunRejectsIncompleteOAuth(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	t.Setenv("BATESIAN_TOKEN", "")
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "target", "https://target.example.com")
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "token-url", "")
	setScanFlag(t, "auth-url", "")
	setScanFlag(t, "dry-run", "true")

	err := runScan(scanCmd, nil)
	const want = "OAuth token acquisition requires --client-id and --token-url"
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), configPath) {
		t.Fatalf("error = %v, want %q and config path", err, want)
	}
}

// TestScan_ConfigOutputFieldApplies verifies config output through the command.
func TestScan_ConfigOutputFieldApplies(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	cfgPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(cfgPath, []byte("output: json\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Drain stdout concurrently because the JSON payload exceeds the pipe buffer.
	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	var buf bytes.Buffer
	readerDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(readerDone)
	}()

	os.Stdout = w
	rootCmd.SetArgs([]string{"scan", "--target", srv.URL, "--config", cfgPath})
	cmdErr := rootCmd.Execute()
	os.Stdout = stdout
	_ = w.Close()
	defer func() { rootCmd.SetArgs(nil) }()
	<-readerDone
	if cmdErr != nil {
		t.Fatalf("scan: %v", cmdErr)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("config output: json did not produce a JSON payload on stdout: %v; got %.200s", err, buf.String())
	}
	if _, ok := doc["findings"]; !ok {
		t.Errorf("payload missing the findings key: %.200s", buf.String())
	}
	if doc["schema_version"] != float64(scanJSONSchemaVersion) {
		t.Errorf("schema version = %v", doc["schema_version"])
	}
	scanner, ok := doc["scanner"].(map[string]any)
	if !ok || scanner["name"] != "batesian" || scanner["version"] == "" {
		t.Errorf("scanner metadata = %v", doc["scanner"])
	}
	ruleset, ok := doc["ruleset"].(map[string]any)
	if !ok {
		t.Fatalf("ruleset metadata = %v", doc["ruleset"])
	}
	loaded, loadedOK := ruleset["loaded"].(float64)
	selected, selectedOK := ruleset["selected"].(float64)
	if !loadedOK || !selectedOK || loaded < selected || ruleset["sha256"] == "" {
		t.Errorf("ruleset metadata = %v", doc["ruleset"])
	}
	outcomes, ok := doc["rule_outcomes"].([]any)
	if !ok || len(outcomes) != int(selected) {
		t.Errorf("rule outcomes = %v", doc["rule_outcomes"])
	}
}

func TestScan_ConfigLoadErrorStopsScan(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(cfgPath, []byte("protocol: [invalid"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	flag := scanCmd.Flags().Lookup("config")
	oldValue, oldChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		_ = flag.Value.Set(oldValue)
		flag.Changed = oldChanged
	})
	if err := scanCmd.Flags().Set("config", cfgPath); err != nil {
		t.Fatalf("setting config flag: %v", err)
	}

	err := runScan(scanCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "loading configuration") {
		t.Fatalf("expected config load error, got %v", err)
	}
}

const cliRuleYAML = `
id: a2a-cli-test-001
info:
  name: CLI Test Rule
  severity: high
attack:
  protocol: a2a
  type: extcard-unauth-disclosure
`

func TestLoadRules_RejectsIncompletePacks(t *testing.T) {
	t.Run("built-in", func(t *testing.T) {
		fsys := fstest.MapFS{
			"valid.yaml": {Data: []byte(cliRuleYAML)},
			"first.yaml": {Data: []byte(cliRuleYAML + "unexpected: true\n")},
			"second.yml": {Data: []byte(cliRuleYAML + "unknown: true\n")},
		}
		_, err := loadRules(fsys, "")
		if err == nil || !strings.Contains(err.Error(), "first.yaml") || !strings.Contains(err.Error(), "second.yml") {
			t.Fatalf("expected every warning in the error, got %v", err)
		}
	})

	t.Run("extra", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "invalid.yaml"), []byte(cliRuleYAML+"unexpected: true\n"), 0o644); err != nil {
			t.Fatalf("writing rule: %v", err)
		}
		fsys := fstest.MapFS{"valid.yaml": {Data: []byte(cliRuleYAML)}}
		_, err := loadRules(fsys, dir)
		if err == nil || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "invalid.yaml") {
			t.Fatalf("expected extra rule error, got %v", err)
		}
	})
}

func TestLoadRules_AppendsValidExtraRules(t *testing.T) {
	dir := t.TempDir()
	extra := strings.Replace(cliRuleYAML, "a2a-cli-test-001", "a2a-cli-test-002", 1)
	if err := os.WriteFile(filepath.Join(dir, "extra.yaml"), []byte(extra), 0o644); err != nil {
		t.Fatalf("writing rule: %v", err)
	}

	loaded, err := loadRules(fstest.MapFS{"valid.yaml": {Data: []byte(cliRuleYAML)}}, dir)
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d rules, want 2", len(loaded))
	}
}

func TestLoadRules_RejectsDuplicateIDs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		builtInID string
		extraIDs  []string
	}{
		{name: "built-in exact", builtInID: "a2a-cli-test-001"},
		{name: "built-in case", builtInID: "A2A-CLI-TEST-001"},
		{name: "supplemental exact", extraIDs: []string{"extra-001", "extra-001"}},
		{name: "supplemental case", extraIDs: []string{"extra-001", "EXTRA-001"}},
		{name: "across catalogs", extraIDs: []string{"a2a-cli-test-001"}},
		{name: "across catalogs case", extraIDs: []string{"A2A-CLI-TEST-001"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builtins := fstest.MapFS{"first.yaml": {Data: []byte(cliRuleYAML)}}
			if tc.builtInID != "" {
				builtins["second.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(cliRuleYAML,
					"a2a-cli-test-001", tc.builtInID, 1))}
			}
			extraDir := ""
			if len(tc.extraIDs) > 0 {
				extraDir = t.TempDir()
				for i, id := range tc.extraIDs {
					data := strings.Replace(cliRuleYAML, "a2a-cli-test-001", id, 1)
					path := filepath.Join(extraDir, fmt.Sprintf("extra-%d.yaml", i))
					if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if loaded, err := loadRules(builtins, extraDir); err == nil || loaded != nil ||
				!strings.Contains(err.Error(), "duplicate rule ID") {
				t.Fatalf("loadRules returned %d rules, error %v", len(loaded), err)
			}
		})
	}
}

func TestScan_InvalidRulePackStopsBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "invalid.yaml"), []byte(cliRuleYAML+"unexpected: true\n"), 0o644); err != nil {
		t.Fatalf("writing rule: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	var oauthHits, targetHits atomic.Int32
	oauth := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		oauthHits.Add(1)
	}))
	defer oauth.Close()
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()
	t.Setenv("BATESIAN_TOKEN", "")
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "rules-dir", dir)
	setScanFlag(t, "target", target.URL)
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "token-url", oauth.URL)
	setScanFlag(t, "dry-run", "false")

	err := runScan(scanCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid.yaml") {
		t.Fatalf("expected rule load error, got %v", err)
	}
	if oauthHits.Load() != 0 || targetHits.Load() != 0 {
		t.Fatalf("network calls before rule validation: oauth=%d target=%d", oauthHits.Load(), targetHits.Load())
	}
}

func TestScan_DuplicateRuleIDStopsBeforeSelectionAndNetwork(t *testing.T) {
	dir := t.TempDir()
	data := strings.Replace(cliRuleYAML, "a2a-cli-test-001", "A2A-ARTIFACT-TAMPER-001", 1)
	if err := os.WriteFile(filepath.Join(dir, "collision.yaml"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var oauthHits, targetHits atomic.Int32
	oauth := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		oauthHits.Add(1)
	}))
	defer oauth.Close()
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()
	t.Setenv("BATESIAN_TOKEN", "")
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "rules-dir", dir)
	setScanFlag(t, "target", target.URL)
	setScanFlag(t, "protocol", "mcp")
	setScanSliceFlag(t, "rule-ids", []string{"mcp-resources-unauth-001"})
	setScanFlag(t, "output", "sarif")
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "token-url", oauth.URL)
	setScanFlag(t, "dry-run", "false")

	if err := runScan(scanCmd, nil); err == nil || !strings.Contains(err.Error(), "duplicate rule ID") {
		t.Fatalf("expected duplicate rule ID before filtered SARIF output, got %v", err)
	}
	if oauthHits.Load() != 0 || targetHits.Load() != 0 {
		t.Fatalf("network calls before rule validation: oauth=%d target=%d", oauthHits.Load(), targetHits.Load())
	}
}

func TestSelectScanRules_RejectsEmptySelection(t *testing.T) {
	loaded := []*rules.Rule{
		{ID: "a2a-test", Info: rules.RuleInfo{Severity: "high", Tags: []string{"auth"}}, Attack: rules.AttackBlock{Protocol: "a2a"}},
		{ID: "mcp-test", Info: rules.RuleInfo{Severity: "low", Tags: []string{"injection"}}, Attack: rules.AttackBlock{Protocol: "mcp"}},
	}
	tests := []struct {
		name       string
		protocol   string
		severities []string
		tags       []string
		ids        []string
	}{
		{name: "protocol and severity", protocol: "mcp", severities: []string{"high"}},
		{name: "severity", severities: []string{"critical"}},
		{name: "protocol and tag", protocol: "mcp", tags: []string{"auth"}},
		{name: "protocol and ID", protocol: "a2a", ids: []string{"mcp-test"}},
		{name: "severity and ID", severities: []string{"high"}, ids: []string{"mcp-test"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := selectScanRules(loaded, tc.protocol, tc.severities, tc.tags, tc.ids)
			if err == nil || !strings.Contains(err.Error(), "no rules matched") {
				t.Fatalf("expected empty selection error, got %v", err)
			}
		})
	}
}

func TestSelectScanRules_RejectsDuplicatesBeforeFilters(t *testing.T) {
	loaded := []*rules.Rule{
		{ID: "A2A-DUP", Attack: rules.AttackBlock{Protocol: "a2a"}},
		{ID: "a2a-dup", Attack: rules.AttackBlock{Protocol: "a2a"}},
		{ID: "mcp-unique", Attack: rules.AttackBlock{Protocol: "mcp"}},
	}
	if _, err := selectScanRules(loaded, "mcp", nil, nil, []string{"mcp-unique"}); err == nil ||
		!strings.Contains(err.Error(), "duplicate rule ID") {
		t.Fatalf("filtered duplicate was accepted: %v", err)
	}
}

func TestSelectScanRules_RejectsInvalidFilters(t *testing.T) {
	loaded := []*rules.Rule{
		{ID: "a2a-test", Info: rules.RuleInfo{Severity: "high", Tags: []string{"auth"}}, Attack: rules.AttackBlock{Protocol: "a2a"}},
		{ID: "mcp-test", Info: rules.RuleInfo{Severity: "low", Tags: []string{"injection"}}, Attack: rules.AttackBlock{Protocol: "mcp"}},
	}
	tests := []struct {
		name       string
		protocol   string
		severities []string
		tags       []string
		ids        []string
		want       string
	}{
		{name: "invalid protocol last", protocol: "mcp,smtp", want: `unknown protocol "smtp"`},
		{name: "invalid protocol first", protocol: "smtp,mcp", want: `unknown protocol "smtp"`},
		{name: "blank protocol", protocol: " ", want: `unknown protocol ""`},
		{name: "empty protocol token", protocol: "mcp,", want: `unknown protocol ""`},
		{name: "commas only", protocol: " , ", want: `unknown protocol ""`},
		{name: "invalid severity last", severities: []string{"high", "hihg"}, want: `unknown severity "hihg"`},
		{name: "invalid severity first", severities: []string{"hihg", "high"}, want: `unknown severity "hihg"`},
		{name: "protocol reported first", protocol: "smtp", severities: []string{"urgent"}, want: `unknown protocol "smtp"`},
		{name: "invalid ID last", ids: []string{"a2a-test", "missing"}, want: `unknown rule ID "missing"`},
		{name: "invalid ID first", ids: []string{"missing", "a2a-test"}, want: `unknown rule ID "missing"`},
		{name: "blank ID", ids: []string{" "}, want: `unknown rule ID ""`},
		{name: "invalid tag last", tags: []string{"auth", "missing"}, want: `unknown tag "missing"`},
		{name: "invalid tag first", tags: []string{"missing", "auth"}, want: `unknown tag "missing"`},
		{name: "blank tag", tags: []string{" "}, want: `unknown tag ""`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := selectScanRules(loaded, tc.protocol, tc.severities, tc.tags, tc.ids)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSelectScanRules_NormalizesFilters(t *testing.T) {
	loaded := []*rules.Rule{
		{ID: "a2a-test", Info: rules.RuleInfo{Severity: "high", Tags: []string{"auth"}}, Attack: rules.AttackBlock{Protocol: "a2a"}},
		{ID: "mcp-test", Info: rules.RuleInfo{Severity: "low", Tags: []string{"injection"}}, Attack: rules.AttackBlock{Protocol: "mcp"}},
	}

	selected, err := selectScanRules(
		loaded,
		" A2A , MCP ",
		[]string{" HIGH ", "low"},
		[]string{" AUTH ", "injection"},
		[]string{" A2A-TEST ", "mcp-test"},
	)
	if err != nil {
		t.Fatalf("selecting rules: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("selected %d rules, want 2", len(selected))
	}
}

func TestSelectScanRules_PreservesEqualFoldMatching(t *testing.T) {
	loaded := []*rules.Rule{{
		ID:     "Σ",
		Info:   rules.RuleInfo{Severity: "high", Tags: []string{"ssrf"}},
		Attack: rules.AttackBlock{Protocol: "a2a"},
	}}

	selected, err := selectScanRules(loaded, "a2a", nil, []string{"ſſrf"}, []string{"ς"})
	if err != nil {
		t.Fatalf("selecting rules: %v", err)
	}
	if len(selected) != 1 || selected[0] != loaded[0] {
		t.Fatalf("selected rules = %v, want input rule", selected)
	}
}

func TestSelectScanRules_AllowsMatches(t *testing.T) {
	loaded := []*rules.Rule{{ID: "a2a-test", Info: rules.RuleInfo{Severity: "high"}, Attack: rules.AttackBlock{Protocol: "a2a"}}}
	selected, err := selectScanRules(loaded, "a2a", []string{"high"}, nil, []string{"a2a-test"})
	if err != nil {
		t.Fatalf("selecting rules: %v", err)
	}
	if len(selected) != 1 || selected[0] != loaded[0] {
		t.Fatalf("selected rules = %v, want input rule", selected)
	}
}

func TestScan_InvalidFilterStopsBeforeNetwork(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	var oauthConnections, targetHits atomic.Int32
	oauth := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	oauth.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			oauthConnections.Add(1)
		}
	}
	oauth.StartTLS()
	defer oauth.Close()
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()
	t.Setenv("BATESIAN_TOKEN", "")
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "rules-dir", "")
	setScanFlag(t, "target", target.URL)
	setScanFlag(t, "protocol", "a2a,smtp")
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "token-url", oauth.URL)
	setScanFlag(t, "dry-run", "false")

	err := runScan(scanCmd, nil)
	if err == nil || !strings.Contains(err.Error(), `unknown protocol "smtp"`) {
		t.Fatalf("expected invalid protocol error, got %v", err)
	}
	if oauthConnections.Load() != 0 || targetHits.Load() != 0 {
		t.Fatalf("network calls before selection: oauth=%d target=%d", oauthConnections.Load(), targetHits.Load())
	}
}

func TestScan_InvalidSelectorsStopBeforeNetwork(t *testing.T) {
	tests := []struct {
		name       string
		configData string
		ruleIDs    []string
		want       string
	}{
		{
			name:       "flag rule IDs",
			configData: "{}\n",
			ruleIDs:    []string{"a2a-artifact-tamper-001", "missing"},
			want:       `unknown rule ID "missing"`,
		},
		{
			name:       "config tags",
			configData: "tags:\n  - auth\n  - missing\n",
			want:       `unknown tag "missing"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "batesian.yaml")
			if err := os.WriteFile(configPath, []byte(tc.configData), 0o644); err != nil {
				t.Fatalf("writing config: %v", err)
			}

			var oauthConnections, targetHits atomic.Int32
			oauth := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			oauth.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					oauthConnections.Add(1)
				}
			}
			oauth.StartTLS()
			defer oauth.Close()
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				targetHits.Add(1)
			}))
			defer target.Close()

			t.Setenv("BATESIAN_TOKEN", "")
			if scanCmd.Flags().Lookup("target") == nil {
				scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
			}
			setScanFlag(t, "config", configPath)
			setScanFlag(t, "rules-dir", "")
			setScanFlag(t, "target", target.URL)
			setScanFlag(t, "protocol", "")
			setScanFlag(t, "token", "")
			setScanFlag(t, "client-id", "client")
			setScanFlag(t, "token-url", oauth.URL)
			setScanFlag(t, "auth-url", "")
			setScanFlag(t, "dry-run", "false")
			if tc.ruleIDs != nil {
				setScanSliceFlag(t, "rule-ids", tc.ruleIDs)
			}

			err := runScan(scanCmd, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if oauthConnections.Load() != 0 || targetHits.Load() != 0 {
				t.Fatalf("network calls before selector validation: oauth=%d target=%d", oauthConnections.Load(), targetHits.Load())
			}
		})
	}
}

func TestScan_InvalidTargetStopsBeforeOAuth(t *testing.T) {
	tests := []struct {
		name       string
		configData string
		target     string
		dryRun     string
	}{
		{name: "flag target", configData: "{}\n", target: "ftp://agent.example.com", dryRun: "false"},
		{name: "config target", configData: "target: ftp://agent.example.com\n", dryRun: "false"},
		{name: "dry run", configData: "{}\n", target: "ftp://agent.example.com", dryRun: "true"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "batesian.yaml")
			if err := os.WriteFile(configPath, []byte(tc.configData), 0o644); err != nil {
				t.Fatalf("writing config: %v", err)
			}

			var oauthConnections atomic.Int32
			oauth := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			oauth.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					oauthConnections.Add(1)
				}
			}
			oauth.StartTLS()
			defer oauth.Close()

			t.Setenv("BATESIAN_TOKEN", "")
			if scanCmd.Flags().Lookup("target") == nil {
				scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
			}
			setScanFlag(t, "config", configPath)
			setScanFlag(t, "rules-dir", "")
			setScanFlag(t, "target", tc.target)
			setScanFlag(t, "token", "")
			setScanFlag(t, "client-id", "client")
			setScanFlag(t, "token-url", oauth.URL)
			setScanFlag(t, "auth-url", "")
			setScanFlag(t, "dry-run", tc.dryRun)

			err := runScan(scanCmd, nil)
			if err == nil || !strings.Contains(err.Error(), "invalid target URL: must use http or https scheme") {
				t.Fatalf("expected target URL error, got %v", err)
			}
			if oauthConnections.Load() != 0 {
				t.Fatalf("OAuth connections before target validation: %d", oauthConnections.Load())
			}
		})
	}
}

func TestScan_EmptySelectionStopsBeforeNetwork(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	configData := "rule_ids:\n  - mcp-resources-unauth-001\n"
	if err := os.WriteFile(configPath, []byte(configData), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	var oauthConnections, targetHits atomic.Int32
	oauth := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	oauth.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			oauthConnections.Add(1)
		}
	}
	oauth.StartTLS()
	defer oauth.Close()
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	t.Setenv("BATESIAN_TOKEN", "")
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "rules-dir", "")
	setScanFlag(t, "target", target.URL)
	setScanFlag(t, "protocol", "a2a")
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "token-url", oauth.URL)
	setScanFlag(t, "dry-run", "false")

	err := runScan(scanCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "no rules matched") {
		t.Fatalf("expected empty selection error, got %v", err)
	}
	if oauthConnections.Load() != 0 || targetHits.Load() != 0 {
		t.Fatalf("network calls before selection: oauth=%d target=%d", oauthConnections.Load(), targetHits.Load())
	}
}

func TestScan_InvalidOutputStopsBeforeOAuth(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	var oauthConnections, targetHits atomic.Int32
	oauth := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	oauth.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			oauthConnections.Add(1)
		}
	}
	oauth.StartTLS()
	defer oauth.Close()
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()

	t.Setenv("BATESIAN_TOKEN", "")
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "target", target.URL)
	setScanFlag(t, "output", "jsno")
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "token-url", oauth.URL)
	setScanFlag(t, "dry-run", "false")

	err := runScan(scanCmd, nil)
	if err == nil || !strings.Contains(err.Error(), `unknown output format "jsno"`) || !strings.Contains(err.Error(), configPath) {
		t.Fatalf("expected output format error with config path, got %v", err)
	}
	if oauthConnections.Load() != 0 || targetHits.Load() != 0 {
		t.Fatalf("network calls before output validation: oauth=%d target=%d", oauthConnections.Load(), targetHits.Load())
	}
}

func TestScan_InvalidOutputStopsBeforePKCE(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	t.Setenv("BATESIAN_TOKEN", "")
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "target", "https://target.example.com")
	setScanFlag(t, "output", "xml")
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "auth-url", "http://auth.example.com/authorize")
	setScanFlag(t, "token-url", "https://auth.example.com/token")
	setScanFlag(t, "no-browser", "true")
	setScanFlag(t, "dry-run", "false")

	err := runScan(scanCmd, nil)
	if err == nil || !strings.Contains(err.Error(), `unknown output format "xml"`) || !strings.Contains(err.Error(), configPath) {
		t.Fatalf("expected output format error with config path, got %v", err)
	}
}

func setScanFlag(t *testing.T, name, value string) {
	t.Helper()
	flag := scanCmd.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("unknown scan flag %q", name)
	}
	oldValue, oldChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		_ = flag.Value.Set(oldValue)
		flag.Changed = oldChanged
	})
	if err := flag.Value.Set(value); err != nil {
		t.Fatalf("setting %s: %v", name, err)
	}
	flag.Changed = true
}

func setScanSliceFlag(t *testing.T, name string, values []string) {
	t.Helper()
	flag := scanCmd.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("unknown scan flag %q", name)
	}
	slice, ok := flag.Value.(interface {
		GetSlice() []string
		Replace([]string) error
	})
	if !ok {
		t.Fatalf("scan flag %q is not a slice", name)
	}
	oldValues, oldChanged := append([]string(nil), slice.GetSlice()...), flag.Changed
	t.Cleanup(func() {
		_ = slice.Replace(oldValues)
		flag.Changed = oldChanged
	})
	if err := slice.Replace(values); err != nil {
		t.Fatalf("setting %s: %v", name, err)
	}
	flag.Changed = true
}
