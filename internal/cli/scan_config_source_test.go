package cli

import (
	"context"
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
