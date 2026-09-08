package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	batesian "github.com/calbebop/batesian"
	"github.com/calbebop/batesian/internal/report"
	"github.com/calbebop/batesian/internal/rules"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules [rule-id]",
	Short: "List bundled rules or describe one in detail",
	Long: `List every bundled rule with its protocol, severity, and name, or pass a
rule ID to see the full description, tags, references, and remediation.`,
	Example: `  # List all rules
  batesian rules

  # Filter by protocol and severity
  batesian rules --protocol mcp --severity critical,high

  # Describe a single rule
  batesian rules mcp-dns-rebind-origin-001

  # Machine-readable output
  batesian rules --output json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRules,
}

func init() {
	rulesCmd.Flags().StringP("protocol", "p", "", "Filter by protocol: a2a, mcp")
	rulesCmd.Flags().StringSlice("severity", nil, "Filter by severity: critical,high,medium,low,info")
	rulesCmd.Flags().StringSlice("tags", nil, "Filter by tags (comma-separated)")
	rootCmd.AddCommand(rulesCmd)
}

func runRules(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	format, err := parseRulesFormat(outputFmt)
	if err != nil {
		return err
	}

	loaded, err := loadRules(batesian.RulesFS(), "")
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	if len(args) == 1 {
		return describeRule(cmd.OutOrStdout(), loaded, args[0], format)
	}

	protocol, _ := cmd.Flags().GetString("protocol")
	severities, _ := cmd.Flags().GetStringSlice("severity")
	tags, _ := cmd.Flags().GetStringSlice("tags")

	filtered := filterRules(loaded, protocol, severities, tags)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].ID < filtered[j].ID
	})

	switch format {
	case report.FormatJSON:
		return outputRulesJSON(cmd.OutOrStdout(), filtered)
	default:
		outputRulesTable(cmd.OutOrStdout(), filtered)
		return nil
	}
}

func parseRulesFormat(value string) (report.Format, error) {
	format, err := report.ParseFormat(value)
	if err != nil {
		return report.FormatTable, fmt.Errorf("unknown output format %q; supported: table, json", value)
	}
	if format == report.FormatSARIF {
		return report.FormatTable, fmt.Errorf("--output sarif is not supported for rules; use table or json")
	}
	return format, nil
}

func filterRules(rs []*rules.Rule, protocol string, severities, tags []string) []*rules.Rule {
	var out []*rules.Rule
	for _, r := range rs {
		if protocol != "" && r.Attack.Protocol != protocol {
			continue
		}
		if len(severities) > 0 && !containsAny(r.Info.Severity, severities) {
			continue
		}
		if len(tags) > 0 && !hasAnyTag(r.Info.Tags, tags) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func outputRulesTable(w io.Writer, rs []*rules.Rule) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ID\tPROTOCOL\tSEVERITY\tNAME")
	for _, r := range rs {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", r.ID, r.Attack.Protocol, r.Info.Severity, r.Info.Name)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d rule(s)\n", len(rs))
}

func outputRulesJSON(w io.Writer, rs []*rules.Rule) error {
	type jsonRule struct {
		ID       string   `json:"id"`
		Protocol string   `json:"protocol"`
		Severity string   `json:"severity"`
		Name     string   `json:"name"`
		Tags     []string `json:"tags"`
	}
	out := make([]jsonRule, len(rs))
	for i, r := range rs {
		out[i] = jsonRule{
			ID:       r.ID,
			Protocol: r.Attack.Protocol,
			Severity: r.Info.Severity,
			Name:     r.Info.Name,
			Tags:     r.Info.Tags,
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func describeRule(w io.Writer, rs []*rules.Rule, id string, format report.Format) error {
	for _, r := range rs {
		if r.ID == id {
			if format == report.FormatJSON {
				return outputRuleJSON(w, r)
			}
			fmt.Fprintf(w, "ID:          %s\n", r.ID)
			fmt.Fprintf(w, "Name:        %s\n", r.Info.Name)
			fmt.Fprintf(w, "Protocol:    %s\n", r.Attack.Protocol)
			fmt.Fprintf(w, "Severity:    %s\n", r.Info.Severity)
			if len(r.Info.Tags) > 0 {
				fmt.Fprintf(w, "Tags:        %s\n", strings.Join(r.Info.Tags, ", "))
			}
			fmt.Fprintf(w, "\n%s\n", r.Info.Description)
			if len(r.Info.References) > 0 {
				fmt.Fprintln(w, "\nReferences:")
				for _, ref := range r.Info.References {
					fmt.Fprintf(w, "  - %s\n", ref)
				}
			}
			if r.Remediation != "" {
				fmt.Fprintf(w, "\nRemediation:\n  %s\n", r.Remediation)
			}
			return nil
		}
	}
	return fmt.Errorf("no rule with ID %q (run 'batesian rules' to list all)", id)
}

func outputRuleJSON(w io.Writer, r *rules.Rule) error {
	out := struct {
		ID          string   `json:"id"`
		Protocol    string   `json:"protocol"`
		Severity    string   `json:"severity"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		References  []string `json:"references"`
		Remediation string   `json:"remediation"`
	}{
		ID:          r.ID,
		Protocol:    r.Attack.Protocol,
		Severity:    r.Info.Severity,
		Name:        r.Info.Name,
		Description: r.Info.Description,
		Tags:        r.Info.Tags,
		References:  r.Info.References,
		Remediation: r.Remediation,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func containsAny(val string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}

func hasAnyTag(ruleTags, filterTags []string) bool {
	for _, ft := range filterTags {
		for _, rt := range ruleTags {
			if strings.EqualFold(ft, rt) {
				return true
			}
		}
	}
	return false
}
