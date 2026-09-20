package engine

import (
	"fmt"
	"strings"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/severity"
)

// vulnClass identifies rules that describe the same failure on one target.
var vulnClass = map[string]string{
	// A server that fails both JWT signature validation (token-replay) and
	// audience binding (oauth-audience) is one broken token validator, not two
	// separate issues.
	"mcp-token-replay-001":   "mcp-token-validation",
	"mcp-oauth-audience-002": "mcp-token-validation",
}

// Coalesce keeps the strongest finding for each class and target when distinct
// rules overlap. It rebuilds affected results without mutating input findings.
func Coalesce(results []RunResult) []RunResult {
	type loc struct{ ri, fi int }

	groups := map[string][]loc{}
	for ri := range results {
		for fi := range results[ri].Findings {
			f := results[ri].Findings[fi]
			class, ok := vulnClass[f.RuleID]
			if !ok {
				continue
			}
			key := class + "\x00" + f.TargetURL
			groups[key] = append(groups[key], loc{ri, fi})
		}
	}

	subsumed := map[loc]bool{}
	notes := map[loc][]string{}
	for _, locs := range groups {
		distinct := map[string]bool{}
		for _, l := range locs {
			distinct[results[l.ri].Findings[l.fi].RuleID] = true
		}
		if len(distinct) < 2 {
			continue // a single rule firing multiple times is not cross-rule overlap
		}
		winner := locs[0]
		for _, l := range locs[1:] {
			if stronger(results[l.ri].Findings[l.fi], results[winner.ri].Findings[winner.fi]) {
				winner = l
			}
		}
		for _, l := range locs {
			if l == winner {
				continue
			}
			subsumed[l] = true
			lf := results[l.ri].Findings[l.fi]
			notes[winner] = append(notes[winner], fmt.Sprintf("%s (%s/%s)", lf.RuleID, lf.Severity, confidenceLabel(lf.Confidence)))
		}
	}

	if len(subsumed) == 0 {
		return results
	}

	out := make([]RunResult, len(results))
	for ri := range results {
		r := results[ri]
		rebuilt := make([]attackpkg.Finding, 0, len(r.Findings))
		for fi := range r.Findings {
			l := loc{ri, fi}
			if subsumed[l] {
				continue
			}
			f := r.Findings[fi]
			if ns, ok := notes[l]; ok {
				note := "Coalesced: subsumes overlapping finding(s) on the same target: " + strings.Join(ns, ", ") + "."
				if f.Evidence == "" {
					f.Evidence = note
				} else {
					f.Evidence = strings.TrimRight(f.Evidence, "\n") + "\n\n" + note
				}
			}
			rebuilt = append(rebuilt, f)
		}
		r.Findings = rebuilt
		out[ri] = r
	}
	return out
}

// stronger reports whether finding a should outrank b (higher confidence first,
// then higher severity).
func stronger(a, b attackpkg.Finding) bool {
	if ca, cb := confidenceRank(a.Confidence), confidenceRank(b.Confidence); ca != cb {
		return ca > cb
	}
	return severityRank(a.Severity) > severityRank(b.Severity)
}

func confidenceRank(c attackpkg.Confidence) int {
	switch c {
	case attackpkg.ConfirmedExploit, "":
		return 2
	case attackpkg.RiskIndicator:
		return 1
	default:
		return 0
	}
}

func confidenceLabel(c attackpkg.Confidence) string {
	if c == "" {
		return string(attackpkg.ConfirmedExploit)
	}
	return string(c)
}

// severityRank uses the shared severity ordering.
func severityRank(s string) int { return severity.Rank(s) }
