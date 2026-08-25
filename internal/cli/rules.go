package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	batesian "github.com/calbebop/batesian"
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
	loaded, _, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	if len(args) == 1 {
		return describeRule(loaded, args[0])
	}

	protocol, _ := cmd.Flags().GetString("protocol")
	severities, _ := cmd.Flags().GetStringSlice("severity")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	outputFmt, _ := cmd.Flags().GetString("output")

	filtered := filterRules(loaded, protocol, severities, tags)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].ID < filtered[j].ID
	})

	switch outputFmt {
	case "json":
		return outputRulesJSON(filtered)
	default:
		outputRulesTable(filtered)
		return nil
	}
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

func outputRulesTable(rs []*rules.Rule) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ID\tPROTOCOL\tSEVERITY\tNAME")
	for _, r := range rs {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", r.ID, r.Attack.Protocol, r.Info.Severity, r.Info.Name)
	}
	tw.Flush()
	fmt.Printf("\n%d rule(s)\n", len(rs))
}

func outputRulesJSON(rs []*rules.Rule) error {
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
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func describeRule(rs []*rules.Rule, id string) error {
	for _, r := range rs {
		if r.ID == id {
			fmt.Printf("ID:          %s\n", r.ID)
			fmt.Printf("Name:        %s\n", r.Info.Name)
			fmt.Printf("Protocol:    %s\n", r.Attack.Protocol)
			fmt.Printf("Severity:    %s\n", r.Info.Severity)
			if len(r.Info.Tags) > 0 {
				fmt.Printf("Tags:        %s\n", strings.Join(r.Info.Tags, ", "))
			}
			fmt.Printf("\n%s\n", r.Info.Description)
			if len(r.Info.References) > 0 {
				fmt.Printf("\nReferences:\n")
				for _, ref := range r.Info.References {
					fmt.Printf("  - %s\n", ref)
				}
			}
			if r.Remediation != "" {
				fmt.Printf("\nRemediation:\n  %s\n", r.Remediation)
			}
			return nil
		}
	}
	return fmt.Errorf("no rule with ID %q (run 'batesian rules' to list all)", id)
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
