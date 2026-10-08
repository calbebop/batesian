package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
)

func TestOutputRedactorScanFormats(t *testing.T) {
	const target = "https://operator:password@example.com/mcp?access_token=secret-value"
	const endpoint = "https://operator:password@example.com/mcp/tools?access_token=secret-value"
	rule := &rules.Rule{ID: "mcp-test-001"}
	result := []engine.RunResult{{
		Rule: rule,
		Findings: []attack.Finding{{
			RuleID:    rule.ID,
			Title:     "Finding at " + target,
			Evidence:  "GET " + endpoint,
			TargetURL: endpoint,
		}},
		Err: errors.New("request failed: " + endpoint),
	}}

	r := newOutputRedactor(target)
	safe := r.results(result)
	if result[0].Findings[0].TargetURL != endpoint {
		t.Fatal("redaction changed the scan result")
	}

	var table, sarif bytes.Buffer
	report.New(&table, true).PrintScanSummary(safe)
	if err := report.WriteSARIF(&sarif, safe, "test"); err != nil {
		t.Fatal(err)
	}
	jsonBody, err := json.Marshal(buildScanJSON(r.displayTarget(), safe))
	if err != nil {
		t.Fatal(err)
	}
	for format, body := range map[string]string{
		"table": table.String(),
		"sarif": sarif.String(),
		"json":  string(jsonBody),
	} {
		for _, secret := range []string{"operator", "password", "secret-value"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s output contains %q", format, secret)
			}
		}
		if !strings.Contains(body, "REDACTED") {
			t.Errorf("%s output lost the redacted target", format)
		}
	}
}

func TestOutputRedactorConfiguredSecrets(t *testing.T) {
	const token = "scan-bearer-secret"
	const principal = "principal-token-secret"
	const endpoint = "https://oauth-user:oauth-password@auth.example/token?key=oauth-query-secret"
	r := newOutputRedactor("https://target.example/mcp")
	r.addURL(endpoint)
	r.addSecret(token)
	r.addSecret(principal)
	results := r.results([]engine.RunResult{{
		Rule: &rules.Rule{ID: "mcp-test-001"},
		Findings: []attack.Finding{{
			RuleID:    "mcp-test-001",
			Title:     token,
			Evidence:  "tokens " + principal + " and " + endpoint,
			TargetURL: "https://target.example/" + token + "?key=" + principal,
		}},
		Err: errors.New("request failed: " + endpoint),
	}})
	var table, sarif bytes.Buffer
	report.New(&table, true).PrintScanSummary(results)
	if err := report.WriteSARIF(&sarif, results, "test"); err != nil {
		t.Fatal(err)
	}
	jsonBody, err := json.Marshal(buildScanJSON(r.displayTarget(), results))
	if err != nil {
		t.Fatal(err)
	}
	for format, body := range map[string]string{
		"table": table.String(), "sarif": sarif.String(), "json": string(jsonBody),
	} {
		for _, secret := range []string{token, principal, "oauth-user", "oauth-password", "oauth-query-secret"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s output disclosed %q", format, secret)
			}
		}
	}
}

func TestCredentialHeader(t *testing.T) {
	for name, want := range map[string]bool{
		"Authorization": true,
		"X-API-Key":     true,
		"Cookie":        true,
		"X-Secret":      true,
		"X-Tenant-Id":   false,
		"X-Env":         false,
		"X-Monkey":      false,
	} {
		if got := credentialHeader(name); got != want {
			t.Errorf("credentialHeader(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestOutputRedactorOverlappingSecrets(t *testing.T) {
	r := newOutputRedactor("https://target.example/short-long-secret")
	r.addSecret("short")
	r.addSecret("short-long-secret")
	if got := r.displayTarget(); strings.Contains(got, "short") || strings.Contains(got, "long-secret") {
		t.Fatalf("target display disclosed part of an overlapping secret: %s", got)
	}
}

func TestOutputRedactorPreservesErrorIdentity(t *testing.T) {
	base := errors.New("request failed")
	err := newOutputRedactor("https://user:password@example.com?token=secret").err(
		errors.Join(base, errors.New("https://user:password@example.com?token=secret")),
	)
	if !errors.Is(err, base) {
		t.Fatal("redaction lost the underlying error")
	}
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaks the target: %v", err)
	}
}

func TestParsePrincipalFlagErrorsHideValues(t *testing.T) {
	for _, raw := range []string{
		"token=secret-value",
		"name=a,header=secret-value",
		"name=a,secret-value",
		"name=a,secret-value=x",
	} {
		_, err := parsePrincipalFlag(raw)
		if err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Errorf("parsePrincipalFlag(%q) error = %v", raw, err)
		}
	}
}

func TestInvalidTargetErrorHidesURL(t *testing.T) {
	const raw = "https://user:password@example.com/%zz?token=secret-value"
	err := validateTargetURL(raw)
	if err == nil || strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("validateTargetURL error = %v", err)
	}
}

func TestCLIInvalidProxyHidesCredentials(t *testing.T) {
	const secret = "proxy-secret-value"
	const proxy = "http://user:" + secret + "@"
	const target = "http://127.0.0.1:1"

	t.Run("probe", func(t *testing.T) {
		if probeCmd.Flags().Lookup("target") == nil {
			probeCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
		}
		setProbeFlag(t, "target", target)
		setProbeFlag(t, "proxy", proxy)
		out, err := captureCLIOutput(t, func() error { return runProbe(probeCmd, nil) })
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(out, secret) {
			t.Fatalf("probe error exposed proxy credentials: %v", err)
		}
	})

	t.Run("scan", func(t *testing.T) {
		if scanCmd.Flags().Lookup("target") == nil {
			scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
		}
		configPath := filepath.Join(t.TempDir(), "batesian.yaml")
		if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		setScanFlag(t, "config", configPath)
		setScanFlag(t, "target", target)
		setScanFlag(t, "proxy", proxy)
		out, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(out, secret) {
			t.Fatalf("scan error exposed proxy credentials: %v", err)
		}
	})

	t.Run("scan config", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "batesian.yaml")
		if err := os.WriteFile(configPath, []byte("proxy: \""+proxy+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		setScanFlag(t, "config", configPath)
		setScanFlag(t, "target", target)
		setScanFlag(t, "proxy", "")
		scanCmd.Flags().Lookup("proxy").Changed = false
		out, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(out, secret) {
			t.Fatalf("scan config error exposed proxy credentials: %v", err)
		}
	})
}

func TestScanErrorsHideConfiguredURLCredentials(t *testing.T) {
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	const secret = "configured-url-secret"
	for _, tc := range []struct {
		name string
		set  func(*testing.T)
	}{
		{"OAuth origin", func(t *testing.T) {
			setScanSliceFlag(t, "oauth-origin", []string{"https://user:" + secret + "@example.com"})
		}},
		{"token URL", func(t *testing.T) {
			setScanFlag(t, "client-id", "client")
			setScanFlag(t, "token-url", "http://user:"+secret+"@example.com/token?key="+secret)
		}},
		{"token request", func(t *testing.T) {
			setScanFlag(t, "client-id", "client")
			setScanFlag(t, "token-url", "https://user:"+secret+"@127.0.0.1:1/token?key="+secret)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "batesian.yaml")
			if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			setScanFlag(t, "config", configPath)
			setScanFlag(t, "target", "http://127.0.0.1:1")
			setScanFlag(t, "token", "")
			setScanFlag(t, "proxy", "")
			setScanFlag(t, "dry-run", "false")
			setScanSliceFlag(t, "rule-ids", []string{"mcp-tools-unauth-001"})
			t.Setenv("BATESIAN_TOKEN", "")
			tc.set(t)
			out, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
			if err == nil {
				t.Fatal("expected configuration error")
			}
			if strings.Contains(out+err.Error(), secret) {
				t.Fatalf("scan output disclosed configured URL credentials: %v", err)
			}
		})
	}
}

func TestProbeOutputHidesBearerToken(t *testing.T) {
	const secret = "probe-bearer-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"Agent","description":"`+secret+`","url":"`+"http://"+r.Host+`","version":"1.0","skills":[]}`)
	}))
	defer server.Close()
	if probeCmd.Flags().Lookup("target") == nil {
		probeCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	previousContext := probeCmd.Context()
	probeCmd.SetContext(context.Background())
	t.Cleanup(func() { probeCmd.SetContext(previousContext) })
	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			setProbeFlag(t, "target", server.URL)
			setProbeFlag(t, "protocol", "a2a")
			setProbeFlag(t, "output", format)
			setProbeFlag(t, "token", secret)
			setProbeFlag(t, "proxy", "")
			out, err := captureCLIOutput(t, func() error { return runProbe(probeCmd, nil) })
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, secret) {
				t.Fatal("probe output disclosed the bearer token")
			}
		})
	}
}

func TestScanDryRunHidesConfiguredTokenInPath(t *testing.T) {
	const secret = "scan-path-secret"
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	previousContext := scanCmd.Context()
	scanCmd.SetContext(context.Background())
	t.Cleanup(func() { scanCmd.SetContext(previousContext) })
	setScanFlag(t, "config", configPath)
	setScanFlag(t, "target", "https://example.com/mcp/"+secret)
	setScanFlag(t, "token", secret)
	setScanFlag(t, "dry-run", "true")
	setScanFlag(t, "proxy", "")
	setScanSliceFlag(t, "rule-ids", []string{"mcp-tools-unauth-001"})
	out, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, secret) {
		t.Fatal("dry run disclosed the configured token")
	}
}

func TestOutputRedactorProbeCard(t *testing.T) {
	r := newOutputRedactor("https://user:password@example.com/mcp?token=secret-value")
	card := map[string]any{
		"url": "https://user:password@example.com/mcp?token=secret-value",
		"interfaces": []any{map[string]any{
			"url": "https://other:pass@example.org/rpc?key=credential",
		}},
	}
	encoded, err := json.Marshal(r.value(card))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"user", "password", "secret-value", "other", "pass", "credential"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("probe JSON contains %q: %s", secret, encoded)
		}
	}
}

func TestOutputRedactorProbeFields(t *testing.T) {
	const target = "https://user:password@example.com/mcp?token=secret-value"
	r := newOutputRedactor(target)
	a2a := &report.ProbeResult{
		Name:   target,
		Skills: []report.SkillSummary{{Description: "See " + target}},
	}
	mcp := &report.MCPProbeResult{
		ServerName: target,
		Tools:      []report.MCPToolSummary{{Description: "See " + target}},
	}
	r.a2aProbeResult(a2a)
	r.mcpProbeResult(mcp)
	for _, value := range []string{a2a.Name, a2a.Skills[0].Description, mcp.ServerName, mcp.Tools[0].Description} {
		if strings.Contains(value, "password") || strings.Contains(value, "secret-value") {
			t.Errorf("probe field contains target credentials: %q", value)
		}
	}
}

func TestScanOutputHidesTargetCredentials(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	target := strings.Replace(server.URL, "http://", "http://operator:password@", 1) + "/mcp?access_token=secret-value"
	configPath := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"table", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			previousContext := scanCmd.Context()
			scanCmd.SetContext(context.Background())
			t.Cleanup(func() { scanCmd.SetContext(previousContext) })
			if scanCmd.Flags().Lookup("target") == nil {
				scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
			}
			setScanFlag(t, "config", configPath)
			setScanFlag(t, "target", target)
			setScanFlag(t, "output", format)
			setScanSliceFlag(t, "rule-ids", []string{"mcp-tools-unauth-001"})
			setScanFlag(t, "dry-run", "false")
			setScanFlag(t, "token", "")
			t.Setenv("BATESIAN_TOKEN", "")

			out, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"operator", "password", "secret-value"} {
				if strings.Contains(out, secret) {
					t.Errorf("%s output contains %q", format, secret)
				}
			}
		})
	}
}

func TestProbeOutputHidesTargetCredentials(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	target := strings.Replace(server.URL, "http://", "http://operator:password@", 1) + "/mcp?access_token=secret-value"
	if probeCmd.Flags().Lookup("target") == nil {
		probeCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	previousContext := probeCmd.Context()
	probeCmd.SetContext(context.Background())
	t.Cleanup(func() { probeCmd.SetContext(previousContext) })
	setProbeFlag(t, "target", target)
	setProbeFlag(t, "protocol", "mcp")
	setProbeFlag(t, "output", "table")
	setProbeFlag(t, "proxy", "")

	out, err := captureCLIOutput(t, func() error { return runProbe(probeCmd, nil) })
	if err == nil {
		t.Fatal("expected a connection error")
	}
	out += err.Error()
	for _, secret := range []string{"operator", "password", "secret-value"} {
		if strings.Contains(out, secret) {
			t.Errorf("probe output contains %q", secret)
		}
	}
}

func captureCLIOutput(t *testing.T, run func() error) (string, error) {
	t.Helper()
	stdout, stderr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	outDone, errDone := make(chan struct{}), make(chan struct{})
	go func() { _, _ = io.Copy(&out, outR); close(outDone) }()
	go func() { _, _ = io.Copy(&diagnostics, errR); close(errDone) }()
	os.Stdout, os.Stderr = outW, errW
	defer func() {
		os.Stdout, os.Stderr = stdout, stderr
		_ = outW.Close()
		_ = errW.Close()
		_ = outR.Close()
		_ = errR.Close()
	}()
	runErr := run()
	_ = outW.Close()
	_ = errW.Close()
	<-outDone
	<-errDone
	return out.String() + diagnostics.String(), runErr
}
