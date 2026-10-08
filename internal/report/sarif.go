package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/severity"
)

// SARIF findings use absolute network URIs, not repository paths.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// GitHub docs: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

const sarifSchema = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
const sarifVersion = "2.1.0"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
	Properties                 sarifCoverage       `json:"properties"`
}

type sarifCoverage struct {
	RulesSelected  int `json:"rulesSelected"`
	RulesCompleted int `json:"rulesCompleted"`
	RulesSkipped   int `json:"rulesSkipped"`
	RulesErrored   int `json:"rulesErrored"`
}

type sarifNotification struct {
	Level          string              `json:"level"`
	Message        sarifMessage        `json:"message"`
	AssociatedRule *sarifRuleReference `json:"associatedRule,omitempty"`
}

type sarifRuleReference struct {
	ID string `json:"id"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	DefaultConfig    sarifRuleConfig     `json:"defaultConfiguration"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"security-severity,omitempty"`
}

type sarifChainStep struct {
	Hop       int    `json:"hop"`
	Principal string `json:"principal,omitempty"`
	Action    string `json:"action"`
	Outcome   string `json:"outcome"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"` // error, warning, note, none
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI         string        `json:"uri"`
	URIBaseID   string        `json:"uriBaseId,omitempty"`
	Description *sarifMessage `json:"description,omitempty"`
}

// WriteSARIF encodes the scan results as SARIF v2.1.0 JSON to w.
func WriteSARIF(w io.Writer, results []engine.RunResult, toolVersion string) error {
	doc := buildSARIF(results, toolVersion)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}
	return nil
}

func buildSARIF(results []engine.RunResult, toolVersion string) sarifLog {
	ruleMap := make(map[string]sarifRule)
	// SARIF requires an array even when the scan finds nothing.
	sarifResults := make([]sarifResult, 0, len(results))
	invocation := buildSARIFInvocation(results)

	for _, r := range results {
		if r.Rule != nil {
			tags := append([]string{"security"}, r.Rule.Info.Tags...)
			ruleMap[r.Rule.ID] = sarifRule{
				ID:               r.Rule.ID,
				Name:             r.Rule.Info.Name,
				ShortDescription: sarifMessage{Text: r.Rule.Info.Name},
				FullDescription:  sarifMessage{Text: truncateRunes(r.Rule.Info.Description, 500)},
				HelpURI:          firstHTTPReference(r.Rule.Info.References),
				DefaultConfig:    sarifRuleConfig{Level: severityLevel(r.Rule.Info.Severity)},
				Properties: sarifRuleProperties{
					Tags:     tags,
					Severity: severityScore(r.Rule.Info.Severity),
				},
			}
		}
	}
	for _, r := range results {
		for _, f := range r.Findings {
			result := findingToSARIF(f)
			if base, ok := ruleMap[f.RuleID]; ok &&
				(severity.Canonical(f.Severity) == "" || base.Properties.Severity != severityScore(f.Severity)) {
				variant := base
				variantSeverity := severity.Canonical(f.Severity)
				if variantSeverity == "" {
					variantSeverity = "unknown"
					variant.Properties.Severity = ""
				} else {
					variant.Properties.Severity = severityScore(f.Severity)
				}
				variant.ID = f.RuleID + "/" + variantSeverity
				variant.DefaultConfig.Level = severityLevel(f.Severity)
				ruleMap[variant.ID] = variant
				result.RuleID = variant.ID
			}
			sarifResults = append(sarifResults, result)
		}
	}

	ruleIDs := make([]string, 0, len(ruleMap))
	for id := range ruleMap {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleMap))
	for _, id := range ruleIDs {
		rules = append(rules, ruleMap[id])
	}

	if toolVersion == "" {
		toolVersion = "dev"
	}

	return sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "batesian",
						Version:        toolVersion,
						InformationURI: "https://github.com/calbebop/batesian",
						Rules:          rules,
					},
				},
				Invocations: []sarifInvocation{invocation},
				Results:     sarifResults,
			},
		},
	}
}

func buildSARIFInvocation(results []engine.RunResult) sarifInvocation {
	var invocation sarifInvocation
	invocation.Properties.RulesSelected = len(results)

	for _, result := range results {
		switch {
		case result.Err != nil:
			invocation.Properties.RulesErrored++
			invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications,
				newSARIFNotification(result, "error", result.Err.Error()))
		case result.Skipped:
			invocation.Properties.RulesSkipped++
			reason := result.SkipMsg
			if reason == "" {
				reason = "rule did not complete"
			}
			invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications,
				newSARIFNotification(result, "warning", reason))
		default:
			invocation.Properties.RulesCompleted++
		}
	}

	invocation.ExecutionSuccessful = invocation.Properties.RulesCompleted == invocation.Properties.RulesSelected
	return invocation
}

func newSARIFNotification(result engine.RunResult, level, detail string) sarifNotification {
	n := sarifNotification{Level: level, Message: sarifMessage{Text: detail}}
	if result.Rule != nil && result.Rule.ID != "" {
		n.AssociatedRule = &sarifRuleReference{ID: result.Rule.ID}
	}
	return n
}

// findingToSARIF converts a Finding into a SARIF result.
func findingToSARIF(f attackpkg.Finding) sarifResult {
	confidence := string(f.EffectiveConfidence())
	props := map[string]any{
		"severity":     severity.CanonicalOrRaw(f.Severity),
		"confidence":   confidence,
		"sourceRuleId": f.RuleID,
	}
	if f.Evidence != "" {
		props["evidence"] = f.Evidence
	}
	if len(f.Chain) > 0 {
		chain := make([]sarifChainStep, 0, len(f.Chain))
		for _, step := range f.Chain {
			chain = append(chain, sarifChainStep{
				Hop: step.Hop, Principal: step.Principal, Action: step.Action, Outcome: step.Outcome,
			})
		}
		props["chain"] = chain
	}
	if len(f.Related) > 0 {
		props["relatedFindings"] = f.Related
	}

	return sarifResult{
		RuleID:  f.RuleID,
		Level:   severityLevel(f.Severity),
		Message: sarifMessage{Text: findingMessage(f)},
		Locations: []sarifLocation{
			{
				PhysicalLocation: sarifPhysicalLocation{
					// Absolute URIs cannot carry uriBaseId.
					ArtifactLocation: sarifArtifactLocation{
						URI: f.TargetURL,
					},
				},
			},
		},
		PartialFingerprints: map[string]string{
			"findingIdentity/v1": fingerprint(f),
		},
		Properties: props,
	}
}

func fingerprint(f attackpkg.Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{f.RuleID, f.Title, fingerprintTarget(f.TargetURL)}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func fingerprintTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.EscapedPath()
}

func findingMessage(f attackpkg.Finding) string {
	parts := make([]string, 0, 4)
	if f.Title != "" {
		parts = append(parts, f.Title)
	}
	if f.Description != "" {
		parts = append(parts, f.Description)
	}
	if f.Evidence != "" {
		parts = append(parts, "Evidence: "+truncateRunes(f.Evidence, 1000))
	}
	if f.Remediation != "" {
		parts = append(parts, "Remediation: "+f.Remediation)
	}
	return strings.Join(parts, "\n\n")
}

// firstHTTPReference selects the alert help link.
func firstHTTPReference(refs []string) string {
	for _, r := range refs {
		if strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://") {
			return r
		}
	}
	return ""
}

// severityLevel maps Batesian severity to SARIF level.
func severityLevel(sev string) string {
	switch severity.Canonical(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// severityScore maps severity to GitHub's numeric security score.
func severityScore(sev string) string { return severity.SARIFScore(sev) }
