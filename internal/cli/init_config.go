// Package cli implements the batesian command-line interface.
package cli

import (
	"fmt"
	"os"

	"github.com/calbebop/batesian/internal/config"
	"github.com/spf13/cobra"
)

var initConfigCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate an annotated batesian.yaml config file in the current directory",
	Long: `Init writes a fully annotated batesian.yaml example to the current directory.
Edit the file to set your target, protocol, auth token, and rule preferences.
All fields are optional; CLI flags always override config file values.`,
	Example: `  batesian init
  batesian init > /path/to/project/batesian.yaml`,
	RunE: runInitConfig,
}

func init() {
	rootCmd.AddCommand(initConfigCmd)
}

func runInitConfig(cmd *cobra.Command, args []string) error {
	const filename = "batesian.yaml"

	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("%s already exists in the current directory; delete it first or edit it manually", filename)
	}

	if err := os.WriteFile(filename, []byte(config.Example()), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", filename, err)
	}

	fmt.Printf("Created %s -- edit it to configure your scan targets and rules.\n", filename)
	return nil
}
