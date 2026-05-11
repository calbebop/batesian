package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	batesian "github.com/calbebop/batesian"
	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/auth"
	"github.com/calbebop/batesian/internal/config"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run attack rules against a target agent endpoint",
	Long: `Scan executes Batesian attack rules against a target A2A or MCP endpoint.

Each rule performs an active attack and evaluates assertions against
the responses. Confirmed findings are output as a table, JSON, or
SARIF for GitHub Security tab integration.

Rules are loaded from the built-in rules directory. Use --rules-dir to
specify an additional directory, or --rule-ids to run specific rules.`,
	Example: `  # Scan an A2A agent with all applicable rules
  batesian scan --target https://agent.example.com

  # Scan with specific rule IDs
  batesian scan --target https://agent.example.com --rule-ids a2a-extcard-unauth-001

  # Scan with SARIF output for GitHub Security tab
  batesian scan --target https://agent.example.com --output sarif > results.sarif

  # Scan with a local OOB listener (for push-SSRF detection)
  batesian scan --target https://agent.example.com --oob

  # Scan MCP only
  batesian scan --target https://mcp-server.example.com --protocol mcp`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("protocol", "p", "", "Filter rules by protocol: a2a, mcp (default: all)")
	scanCmd.Flags().StringSlice("rule-ids", nil, "Run only these rule IDs (comma-separated)")
	scanCmd.Flags().StringSlice("severity", nil, "Filter by severity: critical,high,medium,low,info")
	scanCmd.Flags().StringSlice("tags", nil, "Filter by rule tags (comma-separated)")
	scanCmd.Flags().String("rules-dir", "", "Additional rules directory (supplements built-in rules)")
	scanCmd.Flags().String("token", "", "Bearer token for authenticated requests")
	scanCmd.Flags().Int("timeout", 10, "Request timeout in seconds")
	scanCmd.Flags().Bool("skip-tls", false, "Skip TLS certificate verification")
	scanCmd.Flags().Bool("oob", false, "Deprecated: OOB listener is always started when no --oob-url is provided")
	scanCmd.Flags().String("oob-url", "", "External OOB server URL (overrides --oob local listener)")
	scanCmd.Flags().String("config", "", "Path to batesian.yaml config file (default: auto-discover)")
	// OAuth 2.0 flags for automatic token acquisition.
	scanCmd.Flags().String("token-url", "", "OAuth 2.0 token endpoint URL")
	scanCmd.Flags().String("client-id", "", "OAuth 2.0 client ID (used with --token-url or --auth-url)")
	scanCmd.Flags().String("client-secret", "", "OAuth 2.0 client secret (client credentials flow only)")
	scanCmd.Flags().StringSlice("oauth-scopes", nil, "OAuth 2.0 scopes to request (comma-separated)")
	scanCmd.Flags().String("oauth-audience", "", "OAuth 2.0 audience (Auth0/Okta-style)")
	// PKCE authorization code flow (interactive; opens a browser for user consent).
	scanCmd.Flags().String("auth-url", "", "OAuth 2.0 authorization endpoint URL (enables PKCE flow)")
	scanCmd.Flags().Int("redirect-port", 9876, "Local TCP port for the OAuth callback listener (PKCE flow)")
	scanCmd.Flags().Bool("no-browser", false, "Do not auto-open the browser for PKCE consent (print URL only)")
	// Rule-scoped flag for mcp-oauth-audience-002: expected JWT `aud` claim of the
	// target MCP resource server. Distinct from --oauth-audience, which is a
	// request-time parameter used during AS token acquisition (Auth0/Okta dialect).
	scanCmd.Flags().String("audience-claim", "", "Expected JWT aud value for the target MCP server (used by mcp-oauth-audience-002)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	cfg, cfgErr := config.Load(configPath)
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load config file: %v\n", cfgErr)
		cfg = &config.Config{}
	}

	target, _ := cmd.Flags().GetString("target")
	outputFmt, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")
	protocol, _ := cmd.Flags().GetString("protocol")
	ruleIDs, _ := cmd.Flags().GetStringSlice("rule-ids")
	severities, _ := cmd.Flags().GetStringSlice("severity")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	rulesDir, _ := cmd.Flags().GetString("rules-dir")
	token, _ := cmd.Flags().GetString("token")
	timeoutSecs, _ := cmd.Flags().GetInt("timeout")
	skipTLS, _ := cmd.Flags().GetBool("skip-tls")
	oobURL, _ := cmd.Flags().GetString("oob-url")
	audienceClaim, _ := cmd.Flags().GetString("audience-claim")

	if target == "" {
		target = cfg.Target
	}
	if outputFmt == "" {
		outputFmt = cfg.Output
	}
	if protocol == "" {
		protocol = cfg.Protocol
	}
	if len(ruleIDs) == 0 {
		ruleIDs = cfg.RuleIDs
	}
	if len(severities) == 0 {
		severities = cfg.Severities
	}
	if len(tags) == 0 {
		tags = cfg.Tags
	}
	if rulesDir == "" {
		rulesDir = cfg.RulesDir
	}
	if token == "" {
		token = firstNonEmpty(cfg.Token, os.Getenv("BATESIAN_TOKEN"))
	}
	if timeoutSecs == 10 && cfg.TimeoutSeconds > 0 {
		timeoutSecs = cfg.TimeoutSeconds
	}
	if !skipTLS {
		skipTLS = cfg.SkipTLS
	}
	if oobURL == "" {
		oobURL = cfg.OOBURL
	}
	if audienceClaim == "" {
		audienceClaim = cfg.AudienceClaim
	}

	if target == "" {
		return fmt.Errorf("--target is required")
	}

	if token == "" {
		tokenURL, _ := cmd.Flags().GetString("token-url")
		authURL, _ := cmd.Flags().GetString("auth-url")
		clientID, _ := cmd.Flags().GetString("client-id")
		clientSecret, _ := cmd.Flags().GetString("client-secret")
		oauthScopes, _ := cmd.Flags().GetStringSlice("oauth-scopes")
		oauthAudience, _ := cmd.Flags().GetString("oauth-audience")
		redirectPort, _ := cmd.Flags().GetInt("redirect-port")
		noBrowser, _ := cmd.Flags().GetBool("no-browser")

		switch {
		case authURL != "" && clientID != "" && tokenURL != "":
			tok, err := fetchOAuthTokenPKCE(context.Background(), authURL, tokenURL, clientID, oauthScopes, oauthAudience, redirectPort, !noBrowser)
			if err != nil {
				return fmt.Errorf("OAuth PKCE flow failed: %w", err)
			}
			token = tok
		case clientID != "" && tokenURL != "":
			tok, err := fetchOAuthToken(context.Background(), tokenURL, clientID, clientSecret, oauthScopes, oauthAudience)
			if err != nil {
				return fmt.Errorf("OAuth token acquisition failed: %w", err)
			}
			token = tok
		case authURL != "" && (clientID == "" || tokenURL == ""):
			return fmt.Errorf("--auth-url requires --client-id and --token-url for the PKCE flow")
		}
	}

	format, fmtErr := report.ParseFormat(outputFmt)
	if fmtErr != nil {
		return fmtErr
	}
	statusOut := os.Stdout
	if format == report.FormatJSON || format == report.FormatSARIF {
		statusOut = os.Stderr
	}
	printer := report.New(statusOut, verbose)
	printer.Banner()
	printer.ProbeHeader(target, coalesceProtocol(protocol))

	loaded, warns, err := loadRules(rulesDir)
	if err != nil {
		printer.Error("Failed to load rules: " + err.Error())
		return err
	}
	for _, w := range warns {
		printer.Warn(fmt.Sprintf("Skipping malformed rule %s: %v", w.Path, w.Err))
	}

	filter := &rules.Filter{
		Protocols:  splitProtocols(protocol),
		Severities: severities,
		Tags:       tags,
		IDs:        ruleIDs,
	}
	filtered := filter.Apply(loaded)

	if len(filtered) == 0 {
		printer.Warn("No rules matched the current filters. Check --protocol, --rule-ids, --severity, --tags.")
		return nil
	}
	printer.Info(fmt.Sprintf("Running %d rule(s) against %s", len(filtered), target))
	if verbose {
		for _, r := range filtered {
			printer.Verbose(fmt.Sprintf("  [%s] %s", r.Info.Severity, r.ID))
		}
	}

	opts := attackpkg.Options{
		OOBListenerURL: oobURL,
		Token:          token,
		TimeoutSeconds: timeoutSecs,
		SkipTLS:        skipTLS,
		Verbose:        verbose,
		AudienceClaim:  audienceClaim,
	}

	eng := engine.New(opts)
	ctx := context.Background()
	results := eng.Run(ctx, target, filtered)

	switch format {
	case report.FormatSARIF:
		return report.WriteSARIF(os.Stdout, target, results, "dev")
	case report.FormatJSON:
		return printer.PrintJSON(buildScanJSON(target, results))
	default:
		printer.PrintScanSummary(results)
	}
	return nil
}

// loadRules loads built-in rules from the embedded filesystem, with an optional
// override from a local directory on disk (--rules-dir flag).
func loadRules(extraDir string) ([]*rules.Rule, []rules.LoadWarning, error) {
	loaded, warns, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		return nil, warns, fmt.Errorf("loading built-in rules: %w", err)
	}

	if extraDir != "" {
		extra, extraWarns, extraErr := rules.LoadDir(extraDir)
		warns = append(warns, extraWarns...)
		if extraErr != nil {
			return loaded, warns, fmt.Errorf("loading extra rules from %s: %w", extraDir, extraErr)
		}
		loaded = append(loaded, extra...)
	}

	return loaded, warns, nil
}

// coalesceProtocol returns "a2a/mcp" when protocol is empty.
func coalesceProtocol(p string) string {
	if p == "" {
		return "a2a + mcp"
	}
	return p
}

// splitProtocols splits a comma-separated protocol string into a slice.
// Each token is trimmed and lowercased so that values like "a2a, mcp" match correctly.
func splitProtocols(p string) []string {
	if p == "" {
		return nil
	}
	raw := strings.Split(strings.ToLower(p), ",")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// fetchOAuthToken acquires a bearer token via client credentials grant.
func fetchOAuthToken(ctx context.Context, tokenURL, clientID, clientSecret string, scopes []string, audience string) (string, error) {
	tok, err := auth.FetchClientCredentialsToken(ctx, auth.ClientCredentialsConfig{
		TokenURL:     tokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Audience:     audience,
	})
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// fetchOAuthTokenPKCE drives the interactive PKCE flow: opens a browser, listens
// for the OAuth callback on 127.0.0.1, and exchanges the returned code at the
// token endpoint. Status messages are printed to stderr so JSON/SARIF output
// on stdout stays clean.
func fetchOAuthTokenPKCE(ctx context.Context, authURL, tokenURL, clientID string, scopes []string, audience string, redirectPort int, openBrowser bool) (string, error) {
	tok, err := auth.PerformPKCEFlow(ctx, auth.PKCEFlowConfig{
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		ClientID:     clientID,
		Scopes:       scopes,
		Audience:     audience,
		RedirectPort: redirectPort,
		OpenBrowser:  openBrowser,
		Logger: func(format string, args ...interface{}) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// buildScanJSON creates the JSON representation of scan results.
func buildScanJSON(target string, results []engine.RunResult) map[string]interface{} {
	type jsonFinding struct {
		RuleID      string `json:"rule_id"`
		RuleName    string `json:"rule_name"`
		Severity    string `json:"severity"`
		Confidence  string `json:"confidence"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Evidence    string `json:"evidence,omitempty"`
		Remediation string `json:"remediation,omitempty"`
		TargetURL   string `json:"target_url"`
	}

	findings := make([]jsonFinding, 0)
	skipped := make([]map[string]string, 0)

	for _, r := range results {
		for _, f := range r.Findings {
			confidence := string(f.Confidence)
			if confidence == "" {
				confidence = "confirmed"
			}
			findings = append(findings, jsonFinding{
				RuleID:      f.RuleID,
				RuleName:    f.RuleName,
				Severity:    f.Severity,
				Confidence:  confidence,
				Title:       f.Title,
				Description: f.Description,
				Evidence:    f.Evidence,
				Remediation: f.Remediation,
				TargetURL:   f.TargetURL,
			})
		}
		if r.Skipped {
			skipped = append(skipped, map[string]string{
				"rule_id": r.Rule.ID,
				"reason":  r.SkipMsg,
			})
		}
	}

	return map[string]interface{}{
		"target":   target,
		"findings": findings,
		"skipped":  skipped,
		"summary": map[string]int{
			"total":    engine.TotalFindings(results),
			"critical": len(engine.FindingsBySeverity(results)["critical"]),
			"high":     len(engine.FindingsBySeverity(results)["high"]),
			"medium":   len(engine.FindingsBySeverity(results)["medium"]),
			"low":      len(engine.FindingsBySeverity(results)["low"]),
			"info":     len(engine.FindingsBySeverity(results)["info"]),
		},
	}
}
