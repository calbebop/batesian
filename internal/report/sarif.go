package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/severity"
)

// SARIF v2.1.0 output for SARIF consumers (DAST viewers, dashboards) and CI.
// Findings are network targets (absolute URIs), not repository files, so when
// uploaded to GitHub Code Scanning they appear as alerts without source-line
// annotations - GitHub resolves SARIF locations as repository paths.
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// GitHub docs: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

const sarifSchema = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
const sarifVersion = "2.1.0"

// sarifLog is the top-level SARIF document.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
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
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	// Tags must include "security" for GitHub to route findings to the Security tab.
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"security-severity,omitempty"` // CVSS-like 0.0-10.0 string
}

// sarifResult carries partialFingerprints so GitHub code-scanning correlates
// one logical finding to one alert across scans: without it, identity is
// ruleId + artifact URI, and a discovered endpoint that moves (the candidate
// walk appending or dropping a path) re-opens the same vulnerability as a new
// alert. The fingerprint hashes rule ID plus the finding title - both stable
// while the endpoint string is not.
type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"` // error, warning, note, none
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
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
	// De-duplicate rules from the results.
	ruleMap := make(map[string]sarifRule)
	// A clean scan is the most common outcome, and a nil slice here marshals as
	// "results": null. SARIF 2.1.0 types runs[].results as an array - null is
	// not a legal value - so schema-validating consumers (GitHub code-scanning
	// upload, VS Code SARIF viewer) can reject exactly the scans that found
	// nothing. rules below builds with make for the same reason.
	sarifResults := make([]sarifResult, 0, len(results))

	for _, r := range results {
		if r.Rule != nil {
			// Prepend "security" tag so GitHub routes findings to the Security tab.
			tags := append([]string{"security"}, r.Rule.Info.Tags...)
			ruleMap[r.Rule.ID] = sarifRule{
				ID:               r.Rule.ID,
				Name:             r.Rule.Info.Name,
				ShortDescription: sarifMessage{Text: r.Rule.Info.Name},
				FullDescription:  sarifMessage{Text: truncateRunes(r.Rule.Info.Description, 500)},
				HelpURI:          firstHTTPReference(r.Rule.Info.References),
				Properties: sarifRuleProperties{
					Tags:     tags,
					Severity: severityScore(r.Rule.Info.Severity),
				},
			}
		}
		for _, f := range r.Findings {
			sarifResults = append(sarifResults, findingToSARIF(f))
		}
	}

	// Collect unique rules sorted by ID for deterministic output.
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
				Results: sarifResults,
			},
		},
	}
}

// findingToSARIF converts a Finding into a SARIF result.
func findingToSARIF(f attackpkg.Finding) sarifResult {
	confidence := string(f.Confidence)
	if confidence == "" {
		confidence = "confirmed"
	}
	props := map[string]string{
		"severity":   f.Severity,
		"confidence": confidence,
	}
	if f.Evidence != "" {
		// Truncate evidence for SARIF - full evidence goes in table/JSON output.
		props["evidence"] = truncate(f.Evidence, 500)
	}

	return sarifResult{
		RuleID: f.RuleID,
		Level:  severityLevel(f.Severity),
		Message: sarifMessage{
			Text: fmt.Sprintf("%s\n\nRemediation: %s", f.Description, f.Remediation),
		},
		Locations: []sarifLocation{
			{
				PhysicalLocation: sarifPhysicalLocation{
					// Batesian targets are network endpoints, so TargetURL is an
					// absolute URI. Per SARIF 2.1.0 an absolute uri MUST NOT carry a
					// uriBaseId (and %SRCROOT% would be an undefined base id anyway).
					ArtifactLocation: sarifArtifactLocation{
						URI: f.TargetURL,
					},
				},
			},
		},
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash": fingerprint(f),
		},
		Properties: props,
	}
}

// fingerprint derives the stable per-finding identity used for
// partialFingerprints: SHA-256 over rule ID and finding title, hex-encoded.
// Both fields survive endpoint-string drift, which is exactly the churn that
// used to re-open one vulnerability as a fresh alert.
func fingerprint(f attackpkg.Finding) string {
	sum := sha256.Sum256([]byte(f.RuleID + "\x00" + f.Title))
	return hex.EncodeToString(sum[:])
}

// firstHTTPReference picks the first http(s) reference from a rule's
// reference list for helpUri. Rules cite specs and advisories there; GitHub
// code-scanning renders the field as the alert's help link. A rule with no
// http reference (or none at all) yields an empty helpUri, which the
// omitempty tag drops.
func firstHTTPReference(refs []string) string {
	for _, r := range refs {
		if strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://") {
			return r
		}
	}
	return ""
}

// severityLevel maps Batesian severity strings to SARIF level values.
// GitHub Security tab shows:
//
//	error   -> High/Critical
//	warning -> Medium
//	note    -> Low/Info
func severityLevel(sev string) string {
	// Canonicalize first. This switch compared the raw string, so a severity that
	// differed only in case was demoted to "note" here while the engine ranked it
	// as the worst severity there.
	switch severity.Canonical(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// severityScore maps severity to a CVSS-like numeric string for GitHub's
// security-severity tag, which GitHub uses to categorize findings.
//
// It defers to internal/severity. This copy compared the raw string while the
// engine's rank lowercased first, so a severity that differed only in case scored
// as the least severe here and ranked as the worst there.
func severityScore(sev string) string { return severity.SARIFScore(sev) }
