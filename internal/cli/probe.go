package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/calbebop/batesian/internal/httpx"
	"github.com/calbebop/batesian/internal/protocol/a2a"
	"github.com/calbebop/batesian/internal/protocol/mcp"
	"github.com/calbebop/batesian/internal/report"
	"github.com/spf13/cobra"
)

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Probe a target agent endpoint and map the attack surface",
	Long: `Probe performs reconnaissance against a target A2A or MCP endpoint.

For A2A targets, probe fetches the Agent Card, validates its structure,
discovers capabilities and authentication requirements, and flags
attack surface areas for follow-up with the scan command.

For MCP targets, probe runs the initialize handshake then enumerates
all tools, resources, and prompt templates exposed by the server.

Inline checks performed during probe:
  A2A: extendedAgentCard unauthenticated access (a2a-extcard-unauth-001)
       push notification capability presence (a2a-push-ssrf-001)
  MCP: unauthenticated resources/list access (mcp-resources-unauth-001)
       no-auth session flag for OAuth follow-up (mcp-oauth-dcr-001)`,
	Example: `  # Probe an A2A agent
  batesian probe --target https://agent.example.com

  # Probe an MCP server
  batesian probe --target http://localhost:3001 --protocol mcp

  # Probe with JSON output
  batesian probe --target https://agent.example.com --output json

  # Probe with a bearer token
  batesian probe --target https://agent.example.com --token eyJ...`,
	RunE: runProbe,
}

func init() {
	probeCmd.Flags().StringP("protocol", "p", "a2a", "Protocol to probe: a2a, mcp")
	probeCmd.Flags().String("token", "", "Bearer token for authenticated requests")
	probeCmd.Flags().Int("timeout", 10, "Request timeout in seconds")
	probeCmd.Flags().Bool("skip-tls", false, "Skip TLS certificate verification")
	probeCmd.Flags().String("proxy", "", "Route all requests through an intercepting proxy, e.g. 127.0.0.1:8080 (default: honor HTTPS_PROXY/HTTP_PROXY/NO_PROXY); usually paired with --skip-tls")
	rootCmd.AddCommand(probeCmd)
}

func runProbe(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	protocol, _ := cmd.Flags().GetString("protocol")
	outputFmt, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")
	token, _ := cmd.Flags().GetString("token")
	timeoutSecs, _ := cmd.Flags().GetInt("timeout")
	skipTLS, _ := cmd.Flags().GetBool("skip-tls")
	proxy, _ := cmd.Flags().GetString("proxy")
	// Validate once, up front: a broken proxy should not look like an unreachable
	// target.
	if _, err := httpx.ProxyFunc(proxy); err != nil {
		return err
	}

	if target == "" {
		return fmt.Errorf("--target is required")
	}

	format, fmtErr := report.ParseFormat(outputFmt)
	if fmtErr != nil {
		return fmtErr
	}
	if format == report.FormatSARIF {
		return fmt.Errorf("--output sarif is not supported for probe; use scan for SARIF output")
	}
	// In JSON mode, status messages go to stderr so stdout is machine-parseable.
	statusOut := os.Stdout
	if format == report.FormatJSON {
		statusOut = os.Stderr
	}
	printer := report.New(statusOut, verbose)
	printer.Banner()

	switch strings.ToLower(protocol) {
	case "a2a":
		return probeA2A(target, token, timeoutSecs, skipTLS, proxy, format, printer)
	case "mcp":
		return probeMCP(target, token, timeoutSecs, skipTLS, proxy, format, printer)
	default:
		return fmt.Errorf("unknown protocol %q; supported: a2a, mcp", protocol)
	}
}

func probeA2A(target, token string, timeoutSecs int, skipTLS bool, proxy string, format report.Format, printer *report.Printer) error { //nolint:cyclop
	if timeoutSecs <= 0 {
		timeoutSecs = 10
	}
	opts := []a2a.ClientOption{
		a2a.WithTimeout(time.Duration(timeoutSecs) * time.Second),
	}
	if token != "" {
		opts = append(opts, a2a.WithBearerToken(token))
	}
	if skipTLS {
		opts = append(opts, a2a.WithSkipTLSVerify())
	}
	if proxy != "" {
		opts = append(opts, a2a.WithProxy(proxy))
	}

	client, err := a2a.NewClient(target, opts...)
	if err != nil {
		return err
	}

	printer.ProbeHeader(target, "a2a")
	ctx := context.Background()

	printer.Verbose("GET " + target + a2a.WellKnownPath)
	card, cardResult, err := client.FetchAgentCard(ctx)
	if err != nil {
		if cardResult != nil && cardResult.StatusCode > 0 {
			printer.Error(fmt.Sprintf("Agent Card fetch failed: HTTP %d from %s", cardResult.StatusCode, cardResult.URL))
			return fmt.Errorf("could not fetch Agent Card: %w", err)
		}
		printer.Error("Agent Card fetch failed: " + err.Error())
		return err
	}
	printer.Verbose(fmt.Sprintf("HTTP %d in %s", cardResult.StatusCode, cardResult.Elapsed.Round(time.Millisecond)))
	printer.Success("Agent Card retrieved")

	result := cardToProbeResult(card, cardResult.Elapsed)

	if card.SupportsExtendedCard() {
		printer.Verbose("Probing extended agent card (unauthenticated)...")
		extResult, err := client.ProbeExtendedCard(ctx)
		if err == nil && extResult.IsSuccess() {
			result.Flags = append(result.Flags, report.AttackFlag{
				Severity: "high",
				RuleID:   "a2a-extcard-unauth-001",
				Message:  fmt.Sprintf("/extendedAgentCard returned HTTP %d without authentication", extResult.StatusCode),
			})
		} else if err == nil {
			printer.Verbose(fmt.Sprintf("/extendedAgentCard returned HTTP %d (auth enforced)", extResult.StatusCode))
		}

		printer.Verbose("Probing extended agent card with invalid token...")
		extInvalidResult, err := client.ProbeExtendedCardWithInvalidToken(ctx, "batesian-invalid-probe-token")
		if err == nil && extInvalidResult.IsSuccess() {
			result.Flags = append(result.Flags, report.AttackFlag{
				Severity: "critical",
				RuleID:   "a2a-extcard-unauth-001",
				Message:  "/extendedAgentCard returned HTTP 200 with a fabricated invalid Bearer token",
			})
		}
	}

	if card.Capabilities.PushNotifications {
		result.Flags = append(result.Flags, report.AttackFlag{
			Severity: "info",
			RuleID:   "a2a-push-ssrf-001",
			Message:  "Push notifications enabled. Run scan to test for SSRF via callback URL registration.",
		})
	}

	switch format {
	case report.FormatJSON:
		return report.New(os.Stdout, false).PrintJSON(buildJSONOutput(card, result))
	default:
		printer.PrintProbeTable(result)
	}
	return nil
}

// cardToProbeResult converts an AgentCard to a printable ProbeResult.
func cardToProbeResult(card *a2a.AgentCard, elapsed time.Duration) *report.ProbeResult {
	r := &report.ProbeResult{
		Name:                  card.Name,
		Description:           card.Description,
		URL:                   card.GetServiceURL(),
		Version:               card.Version,
		ProtocolVersion:       card.ProtocolVersion,
		Streaming:             card.Capabilities.Streaming,
		PushNotifications:     card.Capabilities.PushNotifications,
		ExtendedCardAvailable: card.SupportsExtendedCard(),
		AuthRequired:          card.RequiresAuth(),
		Elapsed:               elapsed,
	}

	if card.Provider != nil {
		if card.Provider.URL != "" {
			r.Provider = fmt.Sprintf("%s (%s)", card.Provider.Organization, card.Provider.URL)
		} else {
			r.Provider = card.Provider.Organization
		}
	}

	// Sorted because SecuritySchemes is a map and Go randomizes map iteration, so
	// without this the Schemes row printed a different order between runs and two
	// probes of an unchanged agent were not comparable. Measured over 20 runs on a
	// four-scheme card: three distinct orderings. The JSON output is unaffected,
	// since encoding/json sorts map keys itself.
	for name, scheme := range card.SecuritySchemes {
		r.SecuritySchemes = append(r.SecuritySchemes, name+" ("+scheme.Type()+")")
	}
	sort.Strings(r.SecuritySchemes)

	for _, sk := range card.Skills {
		r.Skills = append(r.Skills, report.SkillSummary{
			ID:          sk.ID,
			Name:        sk.Name,
			Description: sk.Description,
			Tags:        sk.Tags,
		})
	}

	return r
}

func probeMCP(target, token string, timeoutSecs int, skipTLS bool, proxy string, format report.Format, printer *report.Printer) error {
	if timeoutSecs <= 0 {
		timeoutSecs = 10
	}
	opts := []mcp.ClientOption{
		mcp.WithTimeout(time.Duration(timeoutSecs) * time.Second),
	}
	if token != "" {
		opts = append(opts, mcp.WithBearerToken(token))
	}
	if skipTLS {
		opts = append(opts, mcp.WithSkipTLSVerify())
	}
	if proxy != "" {
		opts = append(opts, mcp.WithProxy(proxy))
	}

	client, err := mcp.NewClient(target, opts...)
	if err != nil {
		return err
	}

	printer.ProbeHeader(target, "mcp")
	ctx := context.Background()

	printer.Verbose("POST " + target + "/mcp (initialize)")
	start := time.Now()
	session, err := client.Initialize(ctx)
	elapsed := time.Since(start)
	if err != nil {
		printer.Error("MCP initialize failed: " + err.Error())
		return fmt.Errorf("could not connect to MCP server: %w", err)
	}
	printer.Success(fmt.Sprintf("MCP server connected (%s)", elapsed.Round(time.Millisecond)))

	result := &report.MCPProbeResult{
		ServerName:      session.ServerInfo.Name,
		ServerVersion:   session.ServerInfo.Version,
		ServerTitle:     session.ServerInfo.Title,
		URL:             session.Endpoint,
		ProtocolVersion: session.ProtocolVersion,
		Elapsed:         elapsed,
		HasTools:        session.HasCapability("tools"),
		HasResources:    session.HasCapability("resources"),
		HasPrompts:      session.HasCapability("prompts"),
		HasSampling:     session.HasCapability("sampling"),
		HasLogging:      session.HasCapability("logging"),
	}

	if result.HasTools {
		printer.Verbose("tools/list")
		tools, err := client.ListTools(ctx, session)
		if err == nil {
			for _, t := range tools {
				result.Tools = append(result.Tools, report.MCPToolSummary{
					Name:        t.Name,
					Description: t.Description,
				})
			}
		} else {
			// Silence here reads as "no tools", which is the one conclusion a
			// failed listing can never support - and probe's whole deliverable
			// is the surface map.
			printer.Warn(fmt.Sprintf("tools/list failed: %v (tool surface not enumerated)", err))
		}
	}

	if result.HasResources {
		printer.Verbose("resources/list")
		resources, err := client.ListResources(ctx, session)
		if err == nil && len(resources) > 0 {
			for _, r := range resources {
				result.Resources = append(result.Resources, report.MCPResourceSummary{
					URI:      r.URI,
					MimeType: r.MimeType,
				})
			}
			result.Flags = append(result.Flags, report.AttackFlag{
				Severity: "high",
				RuleID:   "mcp-resources-unauth-001",
				Message:  fmt.Sprintf("%d resource(s) listed without authentication. Run scan to read content.", len(resources)),
			})
		} else if err != nil {
			printer.Warn(fmt.Sprintf("resources/list failed: %v (resource surface not enumerated)", err))
		}
	}

	if result.HasPrompts {
		printer.Verbose("prompts/list")
		prompts, err := client.ListPrompts(ctx, session)
		if err == nil {
			for _, p := range prompts {
				hasReq := false
				for _, a := range p.Arguments {
					if a.Required {
						hasReq = true
						break
					}
				}
				result.Prompts = append(result.Prompts, report.MCPPromptSummary{
					Name:        p.Name,
					ArgCount:    len(p.Arguments),
					HasRequired: hasReq,
				})
			}
		} else {
			printer.Warn(fmt.Sprintf("prompts/list failed: %v (prompt surface not enumerated)", err))
		}
	}

	if token == "" {
		result.Flags = append(result.Flags, report.AttackFlag{
			Severity: "info",
			RuleID:   "mcp-oauth-dcr-001",
			Message:  "No authentication used. Run scan to check OAuth DCR and token validation.",
		})
	}

	switch format {
	case report.FormatJSON:
		return report.New(os.Stdout, false).PrintJSON(result)
	default:
		printer.PrintMCPProbeTable(result)
	}
	return nil
}

// buildJSONOutput creates the JSON representation of a probe result.
func buildJSONOutput(card *a2a.AgentCard, result *report.ProbeResult) map[string]any {
	raw, _ := json.Marshal(card)
	var cardMap map[string]any
	_ = json.Unmarshal(raw, &cardMap)

	flags := make([]map[string]string, 0, len(result.Flags))
	for _, f := range result.Flags {
		flags = append(flags, map[string]string{
			"severity": f.Severity,
			"rule_id":  f.RuleID,
			"message":  f.Message,
		})
	}

	return map[string]any{
		"target":        result.URL,
		"agent_card":    cardMap,
		"attack_flags":  flags,
		"response_time": result.Elapsed.String(),
	}
}
