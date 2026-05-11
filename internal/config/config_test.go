package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/calbebop/batesian/internal/config"
)

func TestLoad_EmptyPath_NoFile(t *testing.T) {
	// Change to a temp dir that has no config file.
	tmp := t.TempDir()
	original, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(original)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Target != "" {
		t.Errorf("expected empty target, got %q", cfg.Target)
	}
}

func TestLoad_ExplicitPath(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "batesian.yaml")
	content := `
target: https://agent.example.com
protocol: mcp
timeout: 30
output: sarif
token: test-token
skip_tls: true
oob: true
oob_url: https://oob.example.com
rule_ids:
  - mcp-tool-poison-001
  - a2a-push-ssrf-001
tags:
  - injection
severities:
  - high
  - critical
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Target != "https://agent.example.com" {
		t.Errorf("target: got %q, want %q", cfg.Target, "https://agent.example.com")
	}
	if cfg.Protocol != "mcp" {
		t.Errorf("protocol: got %q, want mcp", cfg.Protocol)
	}
	if cfg.TimeoutSeconds != 30 {
		t.Errorf("timeout: got %d, want 30", cfg.TimeoutSeconds)
	}
	if cfg.Output != "sarif" {
		t.Errorf("output: got %q, want sarif", cfg.Output)
	}
	if cfg.Token != "test-token" {
		t.Errorf("token: got %q, want test-token", cfg.Token)
	}
	if !cfg.SkipTLS {
		t.Error("expected skip_tls: true")
	}
	if !cfg.OOB {
		t.Error("expected oob: true")
	}
	if cfg.OOBURL != "https://oob.example.com" {
		t.Errorf("oob_url: got %q", cfg.OOBURL)
	}
	if len(cfg.RuleIDs) != 2 {
		t.Errorf("rule_ids: expected 2, got %d", len(cfg.RuleIDs))
	}
	if len(cfg.Tags) != 1 || cfg.Tags[0] != "injection" {
		t.Errorf("tags: expected [injection], got %v", cfg.Tags)
	}
}

func TestLoad_InvalidPath(t *testing.T) {
	_, err := config.Load("/nonexistent/path/batesian.yaml")
	if err == nil {
		t.Error("expected error for nonexistent config path, got nil")
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "batesian.yaml")
	os.WriteFile(cfgPath, []byte("target: [invalid yaml"), 0644)

	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("expected error for malformed YAML, got nil")
	}
}

func TestLoad_InvalidProtocol(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "batesian.yaml")
	os.WriteFile(cfgPath, []byte("protocol: grpc\n"), 0644)
	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid protocol, got nil")
	}
}

func TestLoad_InvalidOutput(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "batesian.yaml")
	os.WriteFile(cfgPath, []byte("output: markdown\n"), 0644)
	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid output format, got nil")
	}
}

func TestLoad_InvalidSeverity(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "batesian.yaml")
	os.WriteFile(cfgPath, []byte("severities:\n  - high\n  - urgent\n"), 0644)
	_, err := config.Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid severity level, got nil")
	}
}

func TestLoad_EmptyProtocolAndOutput_AreValid(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "batesian.yaml")
	os.WriteFile(cfgPath, []byte("target: https://example.com\n"), 0644)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("empty protocol/output should be valid, got: %v", err)
	}
	if cfg.Protocol != "" || cfg.Output != "" {
		t.Error("expected empty protocol and output defaults")
	}
}

func TestExample_IsValidYAML(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "batesian.yaml")
	if err := os.WriteFile(cfgPath, []byte(config.Example()), 0644); err != nil {
		t.Fatalf("writing example config: %v", err)
	}

	// Example config is mostly comments; loading it should succeed and return empty fields.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Example() produced invalid YAML: %v", err)
	}
	// All commented-out fields should be zero-valued.
	if cfg.Target != "" {
		t.Errorf("example config target should be empty, got %q", cfg.Target)
	}
}
