package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	batesian "github.com/calbebop/batesian"
	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/auth"
	"github.com/calbebop/batesian/internal/config"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/httpx"
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
	scanCmd.Flags().String("proxy", "", "Route all requests through an intercepting proxy, e.g. 127.0.0.1:8080 (default: honor HTTPS_PROXY/HTTP_PROXY/NO_PROXY); usually paired with --skip-tls")
	scanCmd.Flags().String("oob-url", "", "External OOB server URL (default: start a local listener automatically)")
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
	// Multi-principal identities for cross-tenant / handoff chained rules.
	// Repeatable; appended to any principals defined in the config file.
	scanCmd.Flags().StringArray("principal", nil, "Extra identity as name=...,token=...,tenant=...,header=Name:Value (repeatable, and header= repeats per identity; for multi-tenant rules)")
	scanCmd.Flags().Bool("no-coalesce", false, "Do not coalesce overlapping findings from rules in the same vulnerability class")
	scanCmd.Flags().Bool("dry-run", false, "Print the requests each rule would send and exit without sending any traffic")
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
	proxy, _ := cmd.Flags().GetString("proxy")
	oobURL, _ := cmd.Flags().GetString("oob-url")
	audienceClaim, _ := cmd.Flags().GetString("audience-claim")
	principalFlags, _ := cmd.Flags().GetStringArray("principal")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

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
	timeoutSecs = effectiveTimeout(cmd.Flags().Changed("timeout"), timeoutSecs, cfg.TimeoutSeconds)
	skipTLS = effectiveSkipTLS(cmd.Flags().Changed("skip-tls"), skipTLS, cfg.SkipTLS)
	// Same sentinel problem as skip-tls: an empty string is indistinguishable from
	// "not passed", so the flag only wins when it was actually set. That lets
	// --proxy="" force a direct connection over a config proxy.
	if !cmd.Flags().Changed("proxy") {
		proxy = cfg.Proxy
	}
	// Validate here rather than letting each rule fail its own requests. A broken
	// proxy is one configuration mistake, and surfacing it as "31 of 36 rules could
	// not reach a testable endpoint" reads as an unreachable target instead.
	if _, err := httpx.ProxyFunc(proxy); err != nil {
		return err
	}
	if oobURL == "" {
		oobURL = cfg.OOBURL
	}
	if audienceClaim == "" {
		audienceClaim = cfg.AudienceClaim
	}

	principals, perr := buildPrincipals(cfg.Principals, principalFlags)
	if perr != nil {
		return perr
	}

	if target == "" {
		return fmt.Errorf("--target is required")
	}

	// A dry run must not reach the network at all, including the authorization
	// server, so skip live OAuth token acquisition. Rules preview as unauthenticated.
	if token == "" && dryRun {
		tokenURL, _ := cmd.Flags().GetString("token-url")
		authURL, _ := cmd.Flags().GetString("auth-url")
		if tokenURL != "" || authURL != "" {
			fmt.Fprintln(os.Stderr, "dry run: skipping OAuth token acquisition; rules preview as unauthenticated")
		}
	}

	if token == "" && !dryRun {
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
		Proxy:          proxy,
		Verbose:        verbose,
		AudienceClaim:  audienceClaim,
		Principals:     principals,
	}

	var recorder *attackpkg.Recorder
	if dryRun {
		recorder = &attackpkg.Recorder{}
		opts.DryRun = true
		opts.Recorder = recorder
	}

	eng := engine.New(opts)
	ctx := context.Background()
	results := eng.Run(ctx, target, filtered)

	if dryRun {
		// No traffic was sent; report the recorded request plan instead of findings.
		printDryRunPlan(os.Stdout, target, recorder)
		return nil
	}

	noCoalesce, _ := cmd.Flags().GetBool("no-coalesce")
	if !noCoalesce {
		results = engine.Coalesce(results)
	}

	switch format {
	case report.FormatSARIF:
		return report.WriteSARIF(os.Stdout, target, results, attackpkg.Version)
	case report.FormatJSON:
		// The machine-readable payload always goes to stdout; status/banner
		// output (above) goes to stderr so `batesian scan --output json | jq`
		// receives clean JSON.
		return report.New(os.Stdout, verbose).PrintJSON(buildScanJSON(target, results))
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

// buildPrincipals merges principals from the config file with any supplied via
// repeatable --principal flags (config first, then flags appended), parsing the
// flag form and rejecting duplicate names so chained rules can reference each
// identity unambiguously.
func buildPrincipals(cfgPrincipals []config.PrincipalConfig, flags []string) ([]attackpkg.Principal, error) {
	var out []attackpkg.Principal
	seen := map[string]bool{}

	add := func(p attackpkg.Principal) error {
		if p.Name == "" {
			return fmt.Errorf("principal is missing a name")
		}
		if seen[p.Name] {
			return fmt.Errorf("duplicate principal name %q", p.Name)
		}
		seen[p.Name] = true
		out = append(out, p)
		return nil
	}

	for _, c := range cfgPrincipals {
		if err := add(attackpkg.Principal{Name: c.Name, Token: c.Token, Tenant: c.Tenant, Headers: c.Headers}); err != nil {
			return nil, err
		}
	}
	for _, raw := range flags {
		p, err := parsePrincipalFlag(raw)
		if err != nil {
			return nil, err
		}
		if err := add(p); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parsePrincipalFlag parses a --principal value of the form
// "name=tenant-a,token=eyJ...,tenant=A,header=X-Tenant-Id:A" into an
// attackpkg.Principal. Recognized keys are name, token, tenant and header; an
// unknown key is an error.
//
// header= is repeatable and each occurrence adds one entry, so a routing header
// does not need a second level of delimiters inside a comma-separated value. The
// value keeps everything after the first colon, which is what lets a header carry
// a URL.
//
// A principal's headers were reachable from the config file but not from this
// flag, even though five multi-principal A2A rules send them. Multi-tenant
// deployments commonly resolve the tenant at a gateway and pass it downstream in a
// header, so without this the CLI could not describe the identities it was asked
// to compare. Measured against an agent that scopes tasks by X-Tenant-Id and
// isolates them correctly: two false-positive cross-tenant findings from the flag
// form, none from the equivalent config file.
//
// One shape still needs the config file: a header value containing a comma, since
// the comma separates segments here.
func parsePrincipalFlag(raw string) (attackpkg.Principal, error) {
	var p attackpkg.Principal
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return p, fmt.Errorf("invalid --principal segment %q; expected key=value", part)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "name":
			p.Name = v
		case "token":
			p.Token = v
		case "tenant":
			p.Tenant = v
		case "header":
			hk, hv, found := strings.Cut(v, ":")
			hk = strings.TrimSpace(hk)
			if !found || hk == "" {
				return p, fmt.Errorf("invalid --principal header %q; expected header=Name:Value", v)
			}
			if p.Headers == nil {
				p.Headers = map[string]string{}
			}
			p.Headers[hk] = strings.TrimSpace(hv)
		case "headers":
			// The config file spells this as a `headers:` map, so it is the first
			// thing an operator tries here.
			return p, fmt.Errorf("use header=Name:Value (repeatable) rather than headers= in --principal")
		default:
			return p, fmt.Errorf("unknown --principal key %q (valid: name, token, tenant, header)", k)
		}
	}
	if p.Name == "" {
		return p, fmt.Errorf("--principal %q is missing name=", raw)
	}
	return p, nil
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

// effectiveTimeout resolves the per-request timeout from the --timeout flag and
// the config file. An explicitly-set flag always wins, even when it equals the
// default, so `--timeout 10` is never silently overridden by a config value.
// Otherwise a positive config value is used; otherwise the flag value (default).
func effectiveTimeout(flagChanged bool, flagVal, cfgVal int) int {
	if !flagChanged && cfgVal > 0 {
		return cfgVal
	}
	return flagVal
}

// effectiveSkipTLS resolves --skip-tls from the flag and config. An explicitly-set
// flag always wins, so `--skip-tls=false` overrides a config `skipTLS: true`
// instead of being masked by the false-is-default sentinel; otherwise the config
// value is used.
func effectiveSkipTLS(flagChanged, flagVal, cfgVal bool) bool {
	if flagChanged {
		return flagVal
	}
	return cfgVal
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

// printDryRunPlan writes the request plan captured during a dry run. Nothing was
// sent; this is the preview an operator reviews before authorizing a real scan.
// Requests are grouped by the rule that issued them, in execution order.
//
// The plan is an approximation, and it diverges in both directions, so it says so
// rather than presenting a count as fact. Measured against
// testdata/mcp_unauth_resources_server.py, 344 recorded against 221 actually sent:
//
//   - Too many endpoint probes. No candidate endpoint can answer in a dry run, so
//     every endpoint-discovery walk runs to exhaustion. The real scan stops at the
//     first endpoint that responds, so it contacted /mcp and never touched /mcp/api
//     or /mcp/mcp at all. The fallback attempts are marked, since those are the
//     ones a real scan mostly skips; the first attempt in each walk is not marked
//     because it is the one that goes out.
//   - Too few follow-ups. A rule that branches on response content cannot proceed
//     past that branch, so its later requests never appear. The real scan sent 92
//     POSTs to /mcp where the plan records 58.
//
// The exhaustive recording is deliberately kept: over-showing endpoint probes is
// the safe bias for a review, and the alternative was measured. Making the
// synthetic response a valid JSON-RPC result envelope, so acceptance-gated walks
// short-circuit like they do live, brought the total closer (202 against 221) but
// silently dropped 32 requests to /mcp/a2a and /mcp/a2a/jsonrpc that a real scan
// does send. A plan used to authorize a scan must not hide traffic.
//
// The host list is exact, which is the part an operator authorizes on. Only the
// counts are approximate.
func printDryRunPlan(out io.Writer, target string, rec *attackpkg.Recorder) {
	reqs := rec.Requests()
	fmt.Fprintf(out, "\nDry run: nothing was sent. Planned requests against %s (%d recorded, see the notes below):\n\n",
		target, len(reqs))

	candidates := endpointCandidateProbes(reqs)

	hosts := map[string]bool{}
	rulesSeen := map[string]bool{}
	marked := 0
	lastRule := "\x00" // sentinel so the first rule (even "") prints a header
	for i, r := range reqs {
		if r.RuleID != lastRule {
			fmt.Fprintf(out, "[%s]\n", dryRunRuleLabel(r.RuleID))
			lastRule = r.RuleID
		}
		rulesSeen[r.RuleID] = true
		suffix := ""
		if candidates[i] {
			suffix = "   [fallback endpoint]"
			marked++
		}
		fmt.Fprintf(out, "  %s %s%s\n", r.Method, r.URL, suffix)
		if u, err := url.Parse(r.URL); err == nil && u.Host != "" {
			hosts[u.Host] = true
		}
		for _, k := range significantHeaderKeys(r.Headers) {
			fmt.Fprintf(out, "      %s: %s\n", k, r.Headers[k])
		}
		if r.Body != "" {
			fmt.Fprintf(out, "      body: %s\n", oneLine(r.Body, 300))
		}
	}

	fmt.Fprintf(out, "\n%d request(s) recorded across %d rule(s) to %d host(s). Nothing was sent.\n",
		len(reqs), len(rulesSeen), len(hosts))
	fmt.Fprintln(out, "The host list above is exact. The counts are not, in both directions:")
	if marked > 0 {
		fmt.Fprintf(out, "  - %d marked [fallback endpoint]: a repeat of an earlier probe at another path.\n", marked)
		fmt.Fprintln(out, "    A real scan stops at the first path that answers, so most of these are not sent.")
	}
	fmt.Fprintln(out, "  - Requests built from live responses (chained follow-ups, acquired tokens, OOB")
	fmt.Fprintln(out, "    callbacks) cannot be expanded here, so a real scan sends more than this.")
}

// endpointCandidateProbes marks the recorded requests that are FALLBACK attempts in
// an endpoint-discovery walk: the same rule sending the same method and body to a
// further URL after an earlier one.
//
// Only the attempts after the first are marked, because the first is the one a real
// scan sends. Marking the whole group would flag 97% of a typical plan and imply
// that all of it is skipped, when in fact one probe per group goes out.
//
// This is derived from what was recorded rather than from any change in behaviour,
// so the plan still lists every candidate. It exists because these entries are the
// ones a real scan mostly does not send, and an unmarked plan invites an operator to
// authorize traffic to paths that will never be contacted.
func endpointCandidateProbes(reqs []attackpkg.RecordedRequest) map[int]bool {
	type probeKey struct{ rule, method, body string }
	urlsFor := map[probeKey]map[string]bool{}
	for _, r := range reqs {
		k := probeKey{r.RuleID, r.Method, r.Body}
		if urlsFor[k] == nil {
			urlsFor[k] = map[string]bool{}
		}
		urlsFor[k][r.URL] = true
	}

	marked := map[int]bool{}
	seenFirst := map[probeKey]bool{}
	for i, r := range reqs {
		k := probeKey{r.RuleID, r.Method, r.Body}
		if len(urlsFor[k]) < 2 {
			continue // a single URL is not a walk
		}
		if !seenFirst[k] {
			seenFirst[k] = true
			continue // the first attempt is the one that is actually sent
		}
		marked[i] = true
	}
	return marked
}

// dryRunRuleLabel labels a recorded request's rule, naming the pre-rule setup
// phase for requests captured before any rule was active.
func dryRunRuleLabel(id string) string {
	if id == "" {
		return "setup"
	}
	return id
}

// significantHeaderKeys returns the request headers worth showing in a dry-run
// plan, sorted. Constant headers (User-Agent, Accept) are omitted as noise.
func significantHeaderKeys(h map[string]string) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		if k == "User-Agent" || k == "Accept" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// oneLine collapses whitespace runs and truncates s for single-line display.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// buildScanJSON creates the JSON representation of scan results.
func buildScanJSON(target string, results []engine.RunResult) map[string]interface{} {
	type jsonChainStep struct {
		Hop       int    `json:"hop"`
		Principal string `json:"principal,omitempty"`
		Action    string `json:"action"`
		Outcome   string `json:"outcome"`
	}
	type jsonFinding struct {
		RuleID      string          `json:"rule_id"`
		RuleName    string          `json:"rule_name"`
		Severity    string          `json:"severity"`
		Confidence  string          `json:"confidence"`
		Title       string          `json:"title"`
		Description string          `json:"description"`
		Evidence    string          `json:"evidence,omitempty"`
		Remediation string          `json:"remediation,omitempty"`
		TargetURL   string          `json:"target_url"`
		Chain       []jsonChainStep `json:"chain,omitempty"`
	}

	findings := make([]jsonFinding, 0)
	skipped := make([]map[string]string, 0)

	for _, r := range results {
		for _, f := range r.Findings {
			confidence := string(f.Confidence)
			if confidence == "" {
				confidence = "confirmed"
			}
			var chain []jsonChainStep
			for _, s := range f.Chain {
				chain = append(chain, jsonChainStep{
					Hop:       s.Hop,
					Principal: s.Principal,
					Action:    s.Action,
					Outcome:   s.Outcome,
				})
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
				Chain:       chain,
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
