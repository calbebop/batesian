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
	jsonBody, err := json.Marshal(buildScanJSON(r.display, safe))
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
