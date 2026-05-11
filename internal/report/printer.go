// Package report handles all output formatting for Batesian findings.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/fatih/color"
)

// Format represents the output format for a report.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// ParseFormat parses a format string into a Format.
// Returns an error for unknown format strings rather than silently defaulting
// to table, so typos like --output=jsno are caught immediately.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "", "table":
		return FormatTable, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	case "markdown", "md":
		return FormatTable, fmt.Errorf("markdown output is not yet implemented; use table, json, or sarif")
	default:
		return FormatTable, fmt.Errorf("unknown output format %q; supported: table, json, sarif", s)
	}
}

// Color helpers — centralized so they can be disabled (e.g. no-color, CI).
var (
	Bold    = color.New(color.Bold).SprintFunc()
	Green   = color.New(color.FgGreen, color.Bold).SprintFunc()
	Yellow  = color.New(color.FgYellow, color.Bold).SprintFunc()
	Red     = color.New(color.FgRed, color.Bold).SprintFunc()
	Cyan    = color.New(color.FgCyan).SprintFunc()
	Dim     = color.New(color.Faint).SprintFunc()
	BoldRed = color.New(color.FgRed, color.Bold).SprintFunc()
)

// Printer writes formatted output to a writer.
type Printer struct {
	w       io.Writer
	verbose bool
}

// New creates a Printer writing to w.
func New(w io.Writer, verbose bool) *Printer {
	return &Printer{w: w, verbose: verbose}
}

// Banner prints the Batesian tool banner.
func (p *Printer) Banner() {
	fmt.Fprintln(p.w)
	fmt.Fprintf(p.w, "  %s  adversarial red-team for AI agent protocols\n", Bold("batesian"))
	fmt.Fprintf(p.w, "  %s\n", Dim("github.com/calbebop/batesian"))
	fmt.Fprintln(p.w)
}

// ProbeHeader prints the probe target header.
func (p *Printer) ProbeHeader(target, protocol string) {
	fmt.Fprintf(p.w, "%s %s  %s\n",
		Cyan(">>"),
		Bold("Probing"),
		target,
	)
	fmt.Fprintf(p.w, "   %s %s\n\n", Dim("protocol:"), protocol)
}

// ProbeResult holds the structured data for a probe result display.
type ProbeResult struct {
	// Basic info
	Name        string
	Description string
	URL         string
	Version     string
	Provider    string

	// Capabilities
	Streaming             bool
	PushNotifications     bool
	ExtendedCardAvailable bool

	// Security
	AuthRequired    bool
	SecuritySchemes []string

	// Skills
	Skills []SkillSummary

	// Attack surface flags
	Flags []AttackFlag

	// Timing
	Elapsed time.Duration
}

// SkillSummary is a condensed view of a skill.
type SkillSummary struct {
	ID          string
	Name        string
	Description string
	Tags        []string
}

// AttackFlag represents a notable finding from the probe phase.
type AttackFlag struct {
	Severity string // "critical", "high", "medium", "low", "info"
	RuleID   string
	Message  string
}

// PrintProbeTable renders the probe result as a formatted table to the terminal.
func (p *Printer) PrintProbeTable(r *ProbeResult) {
	// Agent info section
	p.section("Agent Identity")
	tw := tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
	p.kvRow(tw, "Name", r.Name)
	p.kvRow(tw, "Version", r.Version)
	if r.Description != "" {
		p.kvRow(tw, "Description", truncate(r.Description, 80))
	}
	p.kvRow(tw, "URL", r.URL)
	if r.Provider != "" {
		p.kvRow(tw, "Provider", r.Provider)
	}
	p.kvRow(tw, "Response time", r.Elapsed.Round(time.Millisecond).String())
	tw.Flush()

	// Capabilities
	fmt.Fprintln(p.w)
	p.section("Capabilities")
	tw = tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
	p.kvRow(tw, "Streaming", boolDisplay(r.Streaming))
	p.kvRow(tw, "Push notifications", boolDisplay(r.PushNotifications))
	p.kvRow(tw, "Extended agent card", boolDisplay(r.ExtendedCardAvailable))
	tw.Flush()

	// Authentication
	fmt.Fprintln(p.w)
	p.section("Authentication")
	tw = tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
	if r.AuthRequired {
		p.kvRow(tw, "Auth required", Yellow("yes"))
		if len(r.SecuritySchemes) > 0 {
			p.kvRow(tw, "Schemes", strings.Join(r.SecuritySchemes, ", "))
		}
	} else {
		p.kvRow(tw, "Auth required", Green("no (unauthenticated access)"))
	}
	tw.Flush()

	// Skills
	if len(r.Skills) > 0 {
		fmt.Fprintln(p.w)
		p.section(fmt.Sprintf("Skills (%d)", len(r.Skills)))
		tw = tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", Dim("ID"), Dim("Name"), Dim("Tags"))
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", Dim("--"), Dim("----"), Dim("----"))
		for _, sk := range r.Skills {
			tags := strings.Join(sk.Tags, ", ")
			if tags == "" {
				tags = Dim("none")
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", sk.ID, sk.Name, tags)
		}
		tw.Flush()
	}

	// Attack surface flags
	if len(r.Flags) > 0 {
		fmt.Fprintln(p.w)
		p.section("Attack Surface")
		for _, f := range r.Flags {
			icon, label := severityDisplay(f.Severity)
			fmt.Fprintf(p.w, "  %s %s  %s  %s\n",
				icon,
				label,
				Dim(f.RuleID),
				f.Message,
			)
		}
	}

	fmt.Fprintln(p.w)
}

// PrintJSON marshals v to indented JSON and writes it to the printer's writer.
func (p *Printer) PrintJSON(v any) error {
	enc := json.NewEncoder(p.w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Success prints a success message.
func (p *Printer) Success(msg string) {
	fmt.Fprintf(p.w, "%s %s\n", Green("[+]"), msg)
}

// Info prints an informational message.
func (p *Printer) Info(msg string) {
	fmt.Fprintf(p.w, "%s %s\n", Cyan("[*]"), msg)
}

// Warn prints a warning message.
func (p *Printer) Warn(msg string) {
	fmt.Fprintf(p.w, "%s %s\n", Yellow("[!]"), msg)
}

// Error prints an error message.
func (p *Printer) Error(msg string) {
	fmt.Fprintf(p.w, "%s %s\n", Red("[x]"), msg)
}

// Verbose prints msg only when verbose mode is enabled.
func (p *Printer) Verbose(msg string) {
	if p.verbose {
		fmt.Fprintf(p.w, "%s %s\n", Dim("[~]"), Dim(msg))
	}
}

func (p *Printer) section(title string) {
	fmt.Fprintf(p.w, "%s\n", Bold(title))
}

func (p *Printer) kvRow(tw *tabwriter.Writer, key, value string) {
	fmt.Fprintf(tw, "  %s\t%s\n", Dim(key), value)
}

func boolDisplay(b bool) string {
	if b {
		return Yellow("yes")
	}
	return Dim("no")
}

func severityDisplay(sev string) (icon, label string) {
	switch strings.ToLower(sev) {
	case "critical":
		return BoldRed("[!]"), BoldRed("CRITICAL")
	case "high":
		return Red("[!]"), Red("HIGH")
	case "medium":
		return Yellow("[~]"), Yellow("MEDIUM")
	case "low":
		return Cyan("[~]"), Cyan("LOW")
	default:
		return Dim("[-]"), Dim("INFO")
	}
}

// PrintScanSummary renders the scan results as a terminal table.
func (p *Printer) PrintScanSummary(results []engine.RunResult) {
	total := 0
	for _, r := range results {
		total += len(r.Findings)
	}

	fmt.Fprintln(p.w)
	p.section(fmt.Sprintf("Scan Results (%d finding(s))", total))
	fmt.Fprintln(p.w)

	if total == 0 {
		fmt.Fprintf(p.w, "  %s\n\n", Green("No findings. Target appears clean for the tested rules."))
		return
	}

	// Print findings grouped by severity (critical first).
	bySev := engine.FindingsBySeverity(results)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		findings, ok := bySev[sev]
		if !ok {
			continue
		}
		for _, f := range findings {
			p.printFinding(f)
		}
	}

	// Print rules that were skipped or errored.
	for _, r := range results {
		if r.Skipped {
			p.Verbose(fmt.Sprintf("SKIP %s: %s", r.Rule.ID, r.SkipMsg))
		}
		if r.Err != nil {
			p.Warn(fmt.Sprintf("ERROR running %s: %v", r.Rule.ID, r.Err))
		}
	}
}

// printFinding renders a single finding to the terminal.
func (p *Printer) printFinding(f attackpkg.Finding) {
	icon, label := severityDisplay(f.Severity)

	// Append an [indicator] tag for heuristic findings that are not confirmed exploits.
	confidenceTag := ""
	if f.Confidence == attackpkg.RiskIndicator {
		confidenceTag = " " + Dim("[indicator]")
	}

	fmt.Fprintf(p.w, "%s %s  %s%s\n", icon, label, Bold(f.Title), confidenceTag)
	fmt.Fprintf(p.w, "   %s %s\n", Dim("rule:"), f.RuleID)
	fmt.Fprintf(p.w, "   %s %s\n", Dim("target:"), f.TargetURL)
	if f.Confidence == attackpkg.RiskIndicator {
		fmt.Fprintf(p.w, "   %s %s\n", Dim("note:"), Dim("pattern match only — manual verification recommended"))
	}
	if p.verbose && f.Evidence != "" {
		fmt.Fprintf(p.w, "   %s\n", Dim("evidence:"))
		for _, line := range strings.Split(f.Evidence, "\n") {
			fmt.Fprintf(p.w, "     %s\n", Dim(line))
		}
	}
	fmt.Fprintln(p.w)
}

// MCPProbeResult holds the structured data from an MCP probe.
type MCPProbeResult struct {
	ServerName      string
	ServerVersion   string
	ServerTitle     string
	URL             string
	ProtocolVersion string
	Elapsed         time.Duration

	// Capabilities
	HasTools     bool
	HasResources bool
	HasPrompts   bool
	HasSampling  bool
	HasLogging   bool

	// Enumerated surface
	Tools     []MCPToolSummary
	Resources []MCPResourceSummary
	Prompts   []MCPPromptSummary

	// Attack surface flags
	Flags []AttackFlag
}

// MCPToolSummary is a condensed view of an MCP tool.
type MCPToolSummary struct {
	Name        string
	Description string
}

// MCPResourceSummary is a condensed view of an MCP resource.
type MCPResourceSummary struct {
	URI      string
	MimeType string
}

// MCPPromptSummary is a condensed view of an MCP prompt template.
type MCPPromptSummary struct {
	Name        string
	ArgCount    int
	HasRequired bool
}

// PrintMCPProbeTable renders an MCP probe result to the terminal.
func (p *Printer) PrintMCPProbeTable(r *MCPProbeResult) {
	p.section("Server Identity")
	tw := tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
	name := r.ServerName
	if r.ServerTitle != "" && r.ServerTitle != r.ServerName {
		name = fmt.Sprintf("%s (%s)", r.ServerTitle, r.ServerName)
	}
	p.kvRow(tw, "Name", name)
	p.kvRow(tw, "Version", r.ServerVersion)
	p.kvRow(tw, "Protocol", r.ProtocolVersion)
	p.kvRow(tw, "Endpoint", r.URL)
	p.kvRow(tw, "Response time", r.Elapsed.Round(time.Millisecond).String())
	tw.Flush()

	fmt.Fprintln(p.w)
	p.section("Capabilities")
	tw = tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
	p.kvRow(tw, "Tools", boolDisplay(r.HasTools))
	p.kvRow(tw, "Resources", boolDisplay(r.HasResources))
	p.kvRow(tw, "Prompts", boolDisplay(r.HasPrompts))
	p.kvRow(tw, "Sampling", boolDisplay(r.HasSampling))
	p.kvRow(tw, "Logging", boolDisplay(r.HasLogging))
	tw.Flush()

	if len(r.Tools) > 0 {
		fmt.Fprintln(p.w)
		p.section(fmt.Sprintf("Tools (%d)", len(r.Tools)))
		tw = tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  %s\t%s\n", Dim("Name"), Dim("Description"))
		fmt.Fprintf(tw, "  %s\t%s\n", Dim("----"), Dim("-----------"))
		for _, t := range r.Tools {
			fmt.Fprintf(tw, "  %s\t%s\n", t.Name, truncate(t.Description, 70))
		}
		tw.Flush()
	}

	if len(r.Resources) > 0 {
		fmt.Fprintln(p.w)
		p.section(fmt.Sprintf("Resources (%d)", len(r.Resources)))
		tw = tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  %s\t%s\n", Dim("URI"), Dim("MIME"))
		fmt.Fprintf(tw, "  %s\t%s\n", Dim("---"), Dim("----"))
		for _, r := range r.Resources {
			fmt.Fprintf(tw, "  %s\t%s\n", r.URI, r.MimeType)
		}
		tw.Flush()
	}

	if len(r.Prompts) > 0 {
		fmt.Fprintln(p.w)
		p.section(fmt.Sprintf("Prompt Templates (%d)", len(r.Prompts)))
		tw = tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "  %s\t%s\n", Dim("Name"), Dim("Args"))
		fmt.Fprintf(tw, "  %s\t%s\n", Dim("----"), Dim("----"))
		for _, pr := range r.Prompts {
			req := ""
			if pr.HasRequired {
				req = " (required)"
			}
			fmt.Fprintf(tw, "  %s\t%d%s\n", pr.Name, pr.ArgCount, req)
		}
		tw.Flush()
	}

	if len(r.Flags) > 0 {
		fmt.Fprintln(p.w)
		p.section("Attack Surface")
		for _, f := range r.Flags {
			icon, label := severityDisplay(f.Severity)
			fmt.Fprintf(p.w, "  %s %s  %s  %s\n",
				icon, label, Dim(f.RuleID), f.Message,
			)
		}
	}

	fmt.Fprintln(p.w)
}

// printFinding renders a single finding to the terminal (evidence shown in verbose mode).

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
