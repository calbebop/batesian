// Package config loads and validates Batesian configuration from a batesian.yaml file.
// Values from the file serve as defaults that CLI flags override.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/httpx"
	"gopkg.in/yaml.v3"
)

// defaultFilenames are the config file names searched for in order.
var defaultFilenames = []string{
	"batesian.yaml",
	"batesian.yml",
	".batesian.yaml",
	".batesian.yml",
}

// Config holds the full configuration loaded from a batesian.yaml file.
// All fields are optional; zero values mean "use CLI defaults".
type Config struct {
	// Target is the base URL of the agent or MCP server to scan.
	Target string `yaml:"target"`

	// Protocol filters rules by protocol: "a2a", "mcp", or "" for all.
	Protocol string `yaml:"protocol"`

	// Token is the bearer token used for authenticated requests.
	Token string `yaml:"token"`

	// Output is the output format: "table", "json", "sarif".
	Output string `yaml:"output"`

	// TimeoutSeconds is the per-request HTTP timeout.
	TimeoutSeconds int `yaml:"timeout"`
	// ScanBudgetSeconds limits rule execution; zero disables it.
	ScanBudgetSeconds int `yaml:"scan_budget"`

	// SkipTLS disables TLS certificate verification.
	SkipTLS bool `yaml:"skip_tls"`

	// Proxy routes every request through an intercepting proxy, so a scan can be
	// reviewed in Burp or ZAP. Empty leaves the environment in charge
	// (HTTPS_PROXY, HTTP_PROXY, NO_PROXY).
	Proxy string `yaml:"proxy"`

	// A2AGRPCTarget permits the opt-in A2A gRPC task check at this exact address.
	A2AGRPCTarget string `yaml:"a2a_grpc_target"`

	// OAuthOrigins are exact additional origins that target-advertised OAuth
	// endpoints may use. The target origin itself is always allowed.
	OAuthOrigins []string `yaml:"oauth_origins"`

	// MCPScopeTools are approved calls the limited principal should be denied.
	MCPScopeTools []string `yaml:"mcp_scope_tools"`

	// MCPInvokeTools are exact names the traversal and task rules may call.
	MCPInvokeTools []string `yaml:"mcp_invoke_tools"`

	// MCPSubscriptionProbe permits one explicit update of a disposable resource.
	MCPSubscriptionProbe *MCPSubscriptionProbeConfig `yaml:"mcp_subscription_probe"`

	// MCPFilesystemSuffixProbe tests a disposable filesystem boundary.
	MCPFilesystemSuffixProbe *MCPFilesystemSuffixProbeConfig `yaml:"mcp_filesystem_suffix_probe"`

	// MCPFilesystemSymlinkProbe tests an operator-prepared symlink fixture.
	MCPFilesystemSymlinkProbe *MCPFilesystemSymlinkProbeConfig `yaml:"mcp_filesystem_symlink_probe"`

	// RuleIDs is an explicit list of rule IDs to run.
	RuleIDs []string `yaml:"rule_ids"`

	// Tags filters rules by tag.
	Tags []string `yaml:"tags"`

	// Severities filters rules by severity.
	Severities []string `yaml:"severities"`

	// RulesDir is an additional directory containing custom rule YAML files.
	RulesDir string `yaml:"rules_dir"`

	// OOBURL is the URL of a pre-configured external OOB listener. When empty,
	// the SSRF rule (a2a-push-ssrf-001) starts a local listener automatically.
	OOBURL string `yaml:"oob_url"`

	// AudienceClaim is the expected JWT `aud` value for the target MCP resource
	// server. Used by mcp-oauth-audience-002 to construct canary-mismatch probes.
	// When empty, batesian falls back to RFC 9728 protected-resource-metadata
	// discovery before skipping the rule with Inconclusive.
	AudienceClaim string `yaml:"audience_claim"`

	// MCPCrossAudienceToken is valid for another resource, for the opt-in
	// audience check. An environment reference is recommended.
	MCPCrossAudienceToken string `yaml:"mcp_cross_audience_token"`

	// Principals are additional authenticated identities for multi-tenant and
	// handoff chained rules. Each needs a valid token; cross-tenant isolation
	// rules use two or more to attempt access that must fail.
	Principals []PrincipalConfig `yaml:"principals"`

	// ExpectedDenials are operator-declared access boundaries. They do not
	// change which requests a scan sends.
	ExpectedDenials []ExpectedDenialConfig `yaml:"expected_denials"`
}

// ExpectedDenialConfig names one operation and caller/owner relationship.
type ExpectedDenialConfig struct {
	Operation    string `yaml:"operation"`
	Caller       string `yaml:"caller"`
	CallerTenant string `yaml:"caller_tenant"`
	Owner        string `yaml:"owner"`
	OwnerTenant  string `yaml:"owner_tenant"`
}

// PrincipalConfig is one authenticated identity declared in batesian.yaml.
type PrincipalConfig struct {
	// Name is a logical label for the identity, e.g. "tenant-a".
	Name string `yaml:"name"`
	// Token is the bearer token authenticating this principal.
	Token string `yaml:"token"`
	// Tenant is the tenant/org identifier this principal belongs to.
	Tenant string `yaml:"tenant"`
	// Headers are extra request headers used for tenant routing/scoping.
	Headers map[string]string `yaml:"headers"`
}

// MCPSubscriptionProbeConfig supplies an owner-only update and its resource.
type MCPSubscriptionProbeConfig struct {
	Owner            string                 `yaml:"owner"`
	Caller           string                 `yaml:"caller"`
	ResourceURI      string                 `yaml:"resource_uri"`
	TriggerTool      string                 `yaml:"trigger_tool"`
	TriggerArguments map[string]interface{} `yaml:"trigger_arguments"`
}

// MCPFilesystemSuffixProbeConfig names an allowed directory on the target.
type MCPFilesystemSuffixProbeConfig struct {
	AllowedDirectory string `yaml:"allowed_directory"`
}

type MCPFilesystemSymlinkProbeConfig struct {
	AllowedDirectory string `yaml:"allowed_directory"`
	LinkName         string `yaml:"link_name"`
	OutsidePath      string `yaml:"outside_path"`
	OutsideSizeBytes int64  `yaml:"outside_size_bytes"`
}

// Load reads path or discovers a config in the current directory and its parents.
func Load(path string) (*Config, error) {
	cfg, _, err := LoadWithSource(path)
	return cfg, err
}

// LoadWithSource also returns the absolute path of the loaded file.
// A missing discovered config returns defaults and an empty path.
func LoadWithSource(path string) (*Config, string, error) {
	if path == "" {
		var err error
		path, err = findConfigFile()
		if err != nil {
			return nil, "", err
		}
		if path == "" {
			return &Config{}, "", nil
		}
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("resolving config file %s: %w", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("reading config file %s: %w", path, err)
	}

	var cfg Config
	if err := decodeConfig(data, &cfg); err != nil {
		return nil, "", fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if err := cfg.validate(path); err != nil {
		return nil, "", err
	}

	return &cfg, path, nil
}

func decodeConfig(data []byte, cfg *Config) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return errors.New("multiple YAML documents are not supported")
}

// validate checks that enum fields contain only recognized values.
func (c *Config) validate(path string) error {
	if c.TimeoutSeconds != 0 {
		if _, err := httpx.TimeoutDuration(c.TimeoutSeconds); err != nil {
			return fmt.Errorf("config %s: invalid timeout: %w", path, err)
		}
	}
	if c.ScanBudgetSeconds != 0 {
		if _, err := httpx.TimeoutDuration(c.ScanBudgetSeconds); err != nil {
			return fmt.Errorf("config %s: invalid scan_budget: %w", path, err)
		}
	}
	if c.A2AGRPCTarget != "" {
		if strings.TrimSpace(c.Target) == "" {
			return fmt.Errorf("config %s: a2a_grpc_target requires a target in the same config file", path)
		}
		if _, err := attack.ParseA2AGRPCTarget(c.A2AGRPCTarget); err != nil {
			return fmt.Errorf("config %s: invalid a2a_grpc_target: %w", path, err)
		}
	}

	validProtocols := map[string]bool{"": true, "a2a": true, "mcp": true}
	if !validProtocols[c.Protocol] {
		return fmt.Errorf("config %s: invalid protocol %q; must be \"a2a\", \"mcp\", or omit for all", path, c.Protocol)
	}

	validOutputs := map[string]bool{"": true, "table": true, "json": true, "sarif": true}
	if !validOutputs[c.Output] {
		return fmt.Errorf("config %s: invalid output %q; must be table, json, or sarif", path, c.Output)
	}

	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, s := range c.Severities {
		if !validSeverities[s] {
			return fmt.Errorf("config %s: invalid severity %q; must be critical, high, medium, low, or info", path, s)
		}
	}

	seen := map[string]bool{}
	for i, p := range c.Principals {
		if p.Name == "" {
			return fmt.Errorf("config %s: principals[%d] is missing a name", path, i)
		}
		if seen[p.Name] {
			return fmt.Errorf("config %s: duplicate principal name %q", path, p.Name)
		}
		seen[p.Name] = true
	}
	if c.MCPCrossAudienceToken != "" {
		if strings.TrimSpace(c.Target) == "" {
			return fmt.Errorf("config %s: mcp_cross_audience_token requires a target in the same config file", path)
		}
	}
	if probe := c.MCPSubscriptionProbe; probe != nil {
		if strings.TrimSpace(c.Target) == "" {
			return fmt.Errorf("config %s: mcp_subscription_probe requires a target in the same config file", path)
		}
		if probe.Owner == probe.Caller || !seen[probe.Owner] || !seen[probe.Caller] {
			return fmt.Errorf("config %s: mcp_subscription_probe requires distinct configured owner and caller principals", path)
		}
		uri, err := url.Parse(probe.ResourceURI)
		if probe.ResourceURI == "" || strings.TrimSpace(probe.ResourceURI) != probe.ResourceURI ||
			err != nil || uri.Scheme == "" {
			return fmt.Errorf("config %s: mcp_subscription_probe requires an absolute resource_uri", path)
		}
		if probe.TriggerTool == "" || strings.TrimSpace(probe.TriggerTool) != probe.TriggerTool ||
			probe.TriggerArguments == nil {
			return fmt.Errorf("config %s: mcp_subscription_probe requires trigger_tool and trigger_arguments", path)
		}
		args, err := json.Marshal(probe.TriggerArguments)
		if err != nil || len(args) > 16<<10 {
			return fmt.Errorf("config %s: mcp_subscription_probe trigger_arguments must be JSON-compatible and at most 16 KiB", path)
		}
	}
	if probe := c.MCPFilesystemSuffixProbe; probe != nil {
		if strings.TrimSpace(c.Target) == "" {
			return fmt.Errorf("config %s: mcp_filesystem_suffix_probe requires a target in the same config file", path)
		}
		root := probe.AllowedDirectory
		if !strings.HasPrefix(root, "/") || root == "/" || pathpkg.Clean(root) != root ||
			strings.TrimSpace(root) != root || strings.ContainsAny(root, "'\"\\\r\n\t") {
			return fmt.Errorf("config %s: mcp_filesystem_suffix_probe requires a canonical, non-root POSIX allowed_directory without quotes", path)
		}
	}
	if probe := c.MCPFilesystemSymlinkProbe; probe != nil {
		if strings.TrimSpace(c.Target) == "" {
			return fmt.Errorf("config %s: mcp_filesystem_symlink_probe requires a target in the same config file", path)
		}
		root, outside := probe.AllowedDirectory, probe.OutsidePath
		validPath := func(p string) bool {
			return strings.HasPrefix(p, "/") && p != "/" && pathpkg.Clean(p) == p &&
				strings.TrimSpace(p) == p && !strings.ContainsAny(p, "'\"\\\r\n\t")
		}
		if !validPath(root) || !validPath(outside) || outside == root || strings.HasPrefix(outside, root+"/") {
			return fmt.Errorf("config %s: mcp_filesystem_symlink_probe requires canonical POSIX paths with outside_path outside allowed_directory", path)
		}
		name := probe.LinkName
		if name == "" || name == "." || name == ".." || len(name) > 128 ||
			strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != "" {
			return fmt.Errorf("config %s: mcp_filesystem_symlink_probe requires a simple link_name", path)
		}
		if probe.OutsideSizeBytes < 1024 || probe.OutsideSizeBytes > 65536 || probe.OutsideSizeBytes%512 != 0 {
			return fmt.Errorf("config %s: mcp_filesystem_symlink_probe outside_size_bytes must be 1024..65536 and a multiple of 512", path)
		}
	}
	seenDenials := map[ExpectedDenialConfig]bool{}
	if len(c.ExpectedDenials) > 0 && strings.TrimSpace(c.Target) == "" {
		return fmt.Errorf("config %s: expected_denials requires a target in the same config file", path)
	}
	for i, denial := range c.ExpectedDenials {
		if err := validateExpectedDenial(denial); err != nil {
			return fmt.Errorf("config %s: expected_denials[%d]: %w", path, i, err)
		}
		if seenDenials[denial] {
			return fmt.Errorf("config %s: duplicate expected_denials[%d]", path, i)
		}
		seenDenials[denial] = true
	}

	return nil
}

func validateExpectedDenial(d ExpectedDenialConfig) error {
	for name, value := range map[string]string{
		"operation": d.Operation, "caller": d.Caller, "caller_tenant": d.CallerTenant,
		"owner": d.Owner, "owner_tenant": d.OwnerTenant,
	} {
		if value != strings.TrimSpace(value) {
			return fmt.Errorf("%s must not have surrounding whitespace", name)
		}
	}
	switch d.Operation {
	case attack.MCPPromptsList, attack.MCPPromptsGet, attack.MCPCompletionComplete:
		if d.Caller != "anonymous" || d.Owner != "" || d.CallerTenant != "" || d.OwnerTenant != "" {
			return errors.New("MCP access policy requires caller: anonymous and no owner or tenant")
		}
	case attack.MCPTasksGet, attack.MCPTasksUpdate, attack.MCPTasksCancel, attack.MCPResourcesRead, attack.MCPSessionUse:
		if d.Caller == "" || d.Owner == "" || d.Caller == d.Owner || d.Caller == "anonymous" ||
			d.Caller == "default" || d.Owner == "anonymous" || d.Owner == "default" {
			return errors.New("MCP cross-principal policy requires distinct named caller and owner principals")
		}
	case attack.A2ATasksGet, attack.A2ATasksList:
		if d.Caller != "anonymous" || d.Owner != "default" || d.CallerTenant != "" || d.OwnerTenant != "" {
			return errors.New("A2A task-read policy requires caller: anonymous, owner: default, and no tenant")
		}
	case attack.A2ATasksCancel:
		if d.Caller == "" || d.Owner == "" || d.Caller == d.Owner ||
			(d.Caller == "anonymous" && d.CallerTenant != "") {
			return errors.New("A2A task-cancel policy requires distinct caller and owner names")
		}
	default:
		return fmt.Errorf("unsupported operation %q", d.Operation)
	}
	return nil
}

// findConfigFile searches cwd and parent directories for a config file.
func findConfigFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		for _, name := range defaultFilenames {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			} else if !os.IsNotExist(err) {
				return "", fmt.Errorf("checking config file %s: %w", candidate, err)
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", nil
}

// Example writes an annotated example batesian.yaml to the given path.
func Example() string {
	return `# batesian.yaml -- Batesian configuration file
# All fields are optional. CLI flags override values set here.
# Place this file in your project root or any parent directory.

# Target agent or MCP server URL.
# target: https://agent.example.com

# Protocol filter: "a2a", "mcp", or omit for all protocols.
# protocol: mcp

# Bearer token for authenticated A2A/MCP endpoints.
# Prefer environment variable BATESIAN_TOKEN over committing secrets here.
# token: ""

# Output format: table (default), json, sarif
# output: sarif

# Per-request HTTP timeout in seconds (default: 10).
# timeout: 30

# Overall rule execution budget in seconds; 0 disables it (default).
# scan_budget: 300

# Disable TLS certificate verification (not recommended for production).
# skip_tls: false

# Route every request through an intercepting proxy, so a whole scan can be
# reviewed in Burp or ZAP. A bare host:port is fine. Usually paired with skip_tls,
# since such proxies present their own CA. Omit to honour HTTPS_PROXY/HTTP_PROXY/
# NO_PROXY instead; note that Go does not send loopback targets through an
# environment proxy, so a scan against 127.0.0.1 needs this set explicitly.
# proxy: 127.0.0.1:8080

# Opt-in A2A v1.0 gRPC task-access check. Must match an unscoped Agent Card
# interface and be paired with two principals below. Plaintext is loopback-only.
# The prototype does not support the explicit proxy setting above.
# a2a_grpc_target: grpcs://agent.example.com:50051

# Exact additional origins allowed for target-advertised OAuth endpoints.
# The target origin is always allowed. Add external authorization servers only
# when they are part of the scan scope.
# oauth_origins:
#   - https://login.example.com

# Tools the scope-confusion rule may invoke under all three test identities.
# mcp_scope_tools:
#   - delete_item

# Exact tools the traversal and task rules may call. Review each tool before
# approval; readOnlyHint is supplied by the server and is not a safety guarantee.
# mcp_invoke_tools:
#   - read_file

# Opt-in subscription check against a disposable resource. The owner invokes
# trigger_tool once with these exact arguments. Set target above to lock scope.
# mcp_subscription_probe:
#   owner: tenant-a
#   caller: tenant-b
#   resource_uri: resource://test/disposable
#   trigger_tool: update_test_resource
#   trigger_arguments:
#     value: changed-by-batesian

# Opt-in filesystem boundary probe. Use a disposable POSIX directory and
# approve get_file_info with mcp_invoke_tools above. No file contents are read.
# mcp_filesystem_suffix_probe:
#   allowed_directory: /srv/batesian-disposable

# Opt-in symlink metadata check. Prepare the link and outside file yourself.
# Approve get_file_info and list_directory_with_sizes with mcp_invoke_tools.
# mcp_filesystem_symlink_probe:
#   allowed_directory: /srv/batesian-disposable
#   link_name: outside-link
#   outside_path: /srv/batesian-outside/fixture.bin
#   outside_size_bytes: 1536

# Run only these specific rule IDs (comma-separated in CLI, list here).
# rule_ids:
#   - a2a-push-ssrf-001
#   - mcp-oauth-audience-002

# Filter rules by tag.
# tags:
#   - injection
#   - auth

# Filter rules by minimum severity.
# severities:
#   - critical
#   - high

# Additional directory containing custom YAML rule files.
# rules_dir: ./custom-rules

# External OOB listener URL for SSRF detection (a2a-push-ssrf-001).
# When unset, batesian starts a local listener automatically.
# oob_url: https://your-collaborator.net/token

# Expected JWT 'aud' value for the target MCP resource server.
# Consumed by mcp-oauth-audience-002 to derive canary-mismatch probes
# (substring trap, case-canonicalization trap, array-shape trap).
# When unset, batesian attempts RFC 9728 protected-resource-metadata
# discovery; if that also fails, the rule reports Inconclusive.
# audience_claim: https://api.example.com/mcp

# Opt-in valid-token audience check. Set target above and provide a working
# target token via --token or BATESIAN_TOKEN. Use a token issued by the same
# issuer for a different resource; only the audience rule uses this value.
# mcp_cross_audience_token: "${OTHER_RESOURCE_TOKEN}"

# Additional authenticated identities for multi-tenant / handoff rules.
# Cross-tenant isolation checks use two or more principals to confirm that
# one identity's valid token cannot read another tenant's objects.
# Each principal needs a unique name; supply a token and/or tenant-routing
# headers as the target requires.
# Set the named environment variables before scanning; empty values are rejected.
# principals:
#   - name: tenant-a
#     token: "${BATESIAN_TOKEN_A}"
#     tenant: A
#   - name: tenant-b
#     token: "${BATESIAN_TOKEN_B}"
#     tenant: B
#     headers:
#       X-Tenant-Id: B

# Optional expected denials for observed access. Without these, public access
# findings remain indicators. Names must match configured or CLI principals.
# For A2A task reads, owner: default refers to --token.
# Set target above; a different --target cannot reuse this policy.
# expected_denials:
#   - operation: a2a.tasks.cancel
#     caller: tenant-b
#     caller_tenant: B
#     owner: tenant-a
#     owner_tenant: A
#   - operation: mcp.prompts.get
#     caller: anonymous
#   - operation: mcp.tasks.get
#     caller: tenant-b
#     owner: tenant-a
#   - operation: mcp.resources.read
#     caller: tenant-b
#     owner: tenant-a
#   - operation: mcp.sessions.use
#     caller: tenant-b
#     owner: tenant-a
`
}
