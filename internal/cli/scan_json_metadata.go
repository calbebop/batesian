package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

const scanJSONSchemaVersion = 1

type scanJSONInput struct {
	Target       string
	Reported     []engine.RunResult
	Outcomes     []scanJSONRuleOutcome
	Loaded       []*rules.Rule
	Supplemental bool
}

type scanJSONScanner struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

type scanJSONRuleset struct {
	Source   string `json:"source"`
	Loaded   int    `json:"loaded"`
	Selected int    `json:"selected"`
	SHA256   string `json:"sha256"`
}

type scanJSONRuleOutcome struct {
	RuleID       string `json:"rule_id"`
	Status       string `json:"status"`
	FindingCount int    `json:"finding_count"`
	Reason       string `json:"reason,omitempty"`
	Error        string `json:"error,omitempty"`
}

func buildRuleOutcomes(results []engine.RunResult) []scanJSONRuleOutcome {
	out := make([]scanJSONRuleOutcome, 0, len(results))
	for _, r := range results {
		outcome := scanJSONRuleOutcome{RuleID: r.Rule.ID, FindingCount: len(r.Findings)}
		switch {
		case r.Err != nil:
			outcome.Status = "error"
			outcome.Error = r.Err.Error()
		case r.Skipped:
			outcome.Status = "skipped"
			outcome.Reason = r.SkipMsg
		case len(r.Findings) > 0:
			outcome.Status = "findings"
		default:
			outcome.Status = "no_findings"
		}
		out = append(out, outcome)
	}
	return out
}

func ruleCatalogSHA256(loaded []*rules.Rule) (string, error) {
	encoded := make([]string, len(loaded))
	for i, rule := range loaded {
		data, err := json.Marshal(rule)
		if err != nil {
			return "", fmt.Errorf("hashing ruleset: %w", err)
		}
		encoded[i] = string(data)
	}
	sort.Strings(encoded)
	sum := sha256.Sum256([]byte(strings.Join(encoded, "\n")))
	return hex.EncodeToString(sum[:]), nil
}
