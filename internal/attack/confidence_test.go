package attack_test

import (
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func TestFindingEffectiveConfidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence attack.Confidence
		evidence   string
		want       attack.Confidence
	}{
		{"confirmed with evidence", attack.ConfirmedExploit, "Observed unauthorized task read", attack.ConfirmedExploit},
		{"confirmed without evidence", attack.ConfirmedExploit, "", attack.RiskIndicator},
		{"confirmed with whitespace", attack.ConfirmedExploit, " \n\t", attack.RiskIndicator},
		{"unset with evidence", "", "Observed unauthorized task read", attack.RiskIndicator},
		{"indicator with evidence", attack.RiskIndicator, "Observed suspicious response", attack.RiskIndicator},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := attack.Finding{Confidence: tc.confidence, Evidence: tc.evidence}
			if got := f.EffectiveConfidence(); got != tc.want {
				t.Errorf("EffectiveConfidence() = %q, want %q", got, tc.want)
			}
		})
	}
}
