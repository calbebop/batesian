package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanNoConfigSkipsDiscoveredParent(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "valid", body: "target: https://configured.example.com\n"},
		{name: "malformed", body: "target: [invalid yaml\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			child := filepath.Join(parent, "child")
			if err := os.Mkdir(child, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(parent, "batesian.yaml"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(child)

			if scanCmd.Flags().Lookup("target") == nil {
				scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
			}
			setScanFlag(t, "config", "")
			scanCmd.Flags().Lookup("config").Changed = false
			setScanFlag(t, "no-config", "true")
			setScanFlag(t, "target", "")
			setScanFlag(t, "token", "")
			t.Setenv("BATESIAN_TOKEN", "")

			err := runScan(scanCmd, nil)
			if err == nil || err.Error() != "--target is required" {
				t.Fatalf("error = %v, want missing target", err)
			}
		})
	}
}

func TestScanNoConfigRejectsExplicitConfig(t *testing.T) {
	setScanFlag(t, "config", "batesian.yaml")
	setScanFlag(t, "no-config", "true")

	err := runScan(scanCmd, nil)
	if err == nil || err.Error() != "--config and --no-config cannot be used together" {
		t.Fatalf("error = %v, want conflicting config flags", err)
	}
}

func TestScanReportsConfigSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(path, []byte("target: https://example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", path)
	setScanFlag(t, "no-config", "false")
	setScanFlag(t, "target", "")
	setScanFlag(t, "token", "")
	setScanFlag(t, "output", "table")
	setScanFlag(t, "protocol", "mcp")
	setScanSliceFlag(t, "rule-ids", []string{"mcp-tools-unauth-001"})
	setScanFlag(t, "dry-run", "true")
	t.Setenv("BATESIAN_TOKEN", "")
	previousContext := scanCmd.Context()
	scanCmd.SetContext(context.Background())
	t.Cleanup(func() { scanCmd.SetContext(previousContext) })

	output, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(output, "Loaded config: "+path) {
		t.Fatalf("config source missing from scan output: %.300s", output)
	}
}

func TestScanReportsConfigBeforeOAuthRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "batesian.yaml")
	if err := os.WriteFile(path, []byte("output: json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oauth := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(os.Stderr, "oauth-request-marker")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer oauth.Close()

	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", path)
	setScanFlag(t, "no-config", "false")
	setScanFlag(t, "target", "https://target.example.com")
	setScanFlag(t, "output", "table")
	scanCmd.Flags().Lookup("output").Changed = false
	setScanFlag(t, "token", "")
	setScanFlag(t, "client-id", "client")
	setScanFlag(t, "token-url", oauth.URL)
	setScanFlag(t, "auth-url", "")
	setScanFlag(t, "proxy", "")
	setScanFlag(t, "skip-tls", "true")
	setScanFlag(t, "dry-run", "false")
	setScanSliceFlag(t, "rule-ids", []string{"mcp-tools-unauth-001"})
	t.Setenv("BATESIAN_TOKEN", "")
	previousContext := scanCmd.Context()
	scanCmd.SetContext(context.Background())
	t.Cleanup(func() { scanCmd.SetContext(previousContext) })

	output, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("OAuth error must name selected config: %v", err)
	}
	source := strings.Index(output, "Loaded config: "+path)
	request := strings.Index(output, "oauth-request-marker")
	if source < 0 || request < 0 || source > request {
		t.Fatalf("config source must precede OAuth request: output=%q error=%v", output, err)
	}
}

func TestScanEarlyErrorNamesDiscoveredConfig(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "batesian.yaml")
	if err := os.WriteFile(path, []byte("target: https://target.example.com\nrule_ids: [missing-rule]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)

	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", "")
	scanCmd.Flags().Lookup("config").Changed = false
	setScanFlag(t, "no-config", "false")
	setScanFlag(t, "target", "")
	setScanFlag(t, "output", "table")
	setScanFlag(t, "token", "")
	setScanFlag(t, "proxy", "")
	setScanFlag(t, "client-id", "")
	setScanFlag(t, "token-url", "")
	setScanFlag(t, "auth-url", "")
	setScanSliceFlag(t, "rule-ids", nil)
	t.Setenv("BATESIAN_TOKEN", "")

	output, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
	if err == nil || !strings.Contains(err.Error(), "unknown rule ID") || !strings.Contains(err.Error(), path) {
		t.Fatalf("selection error must name discovered config: %v", err)
	}
	if !strings.Contains(output, "Loaded config: "+path) {
		t.Fatalf("discovered config missing from status: %q", output)
	}
}

func TestScanConfigSourceRedactsKnownSecret(t *testing.T) {
	const secret = "config-path-secret-123"
	dir := filepath.Join(t.TempDir(), secret)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "batesian.yaml")
	if err := os.WriteFile(path, []byte("token: "+secret+"\nproxy: http://user:proxy-secret@\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if scanCmd.Flags().Lookup("target") == nil {
		scanCmd.Flags().AddFlagSet(rootCmd.PersistentFlags())
	}
	setScanFlag(t, "config", path)
	setScanFlag(t, "no-config", "false")
	setScanFlag(t, "target", "https://target.example.com")
	setScanFlag(t, "output", "table")
	setScanFlag(t, "token", "")
	setScanFlag(t, "proxy", "")
	scanCmd.Flags().Lookup("proxy").Changed = false
	setScanFlag(t, "client-id", "")
	setScanFlag(t, "token-url", "")
	setScanFlag(t, "auth-url", "")
	t.Setenv("BATESIAN_TOKEN", "")

	output, err := captureCLIOutput(t, func() error { return runScan(scanCmd, nil) })
	if err == nil || !strings.Contains(err.Error(), "invalid proxy") {
		t.Fatalf("expected proxy validation failure, got %v", err)
	}
	if strings.Contains(output+err.Error(), secret) || strings.Contains(output+err.Error(), "proxy-secret") {
		t.Fatalf("config provenance exposed a secret: %q; %v", output, err)
	}
	if !strings.Contains(output, "Loaded config:") || !strings.Contains(err.Error(), "scan with config") {
		t.Fatalf("missing redacted config provenance: %q; %v", output, err)
	}
}
