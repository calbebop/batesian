package a2a_test

import (
	"strings"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
)

func assertUniqueFindingIdentities(t *testing.T, findings []attack.Finding) {
	t.Helper()
	seen := map[string]bool{}
	for _, finding := range findings {
		key := finding.FingerprintKey
		if key == "" || seen[key] || strings.Contains(key, "token-") || strings.Contains(key, "batesian ") {
			t.Fatalf("missing, duplicate, or unsafe finding identity: %+v", finding)
		}
		seen[key] = true
	}
}
