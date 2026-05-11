package cli

import (
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/spf13/cobra"
)

// SetVersion injects build-time version metadata, called from main.
// The version string is also propagated to the attack package so that every
// outbound HTTP request carries an accurate User-Agent header.
func SetVersion(version, commit, date string) {
	rootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
	attack.Version = version
}

var rootCmd = &cobra.Command{
	Use:   "batesian",
	Short: "Adversarial red-team CLI for AI agent protocols",
	Long: `Batesian is an open-source red-team framework for adversarial testing of
AI agent protocols, specifically A2A (Agent-to-Agent) and MCP (Model Context Protocol).

Unlike passive scanners, Batesian actively probes: it impersonates malicious agent peers,
abuses OAuth flows, fuzzes protocol messages, and finds vulnerabilities that read-only
scanners never see.

Documentation: https://github.com/calbebop/batesian`,
}

// Execute is the entrypoint called by main.
func Execute() error {
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("output", "o", "table", "Output format: table, json, sarif")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringP("target", "t", "", "Target base URL")
}
