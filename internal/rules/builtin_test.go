package rules_test

import (
	"testing"

	batesian "github.com/calbebop/batesian"
	"github.com/calbebop/batesian/internal/rules"
)

func TestBundledRulesLoadWithoutWarnings(t *testing.T) {
	loaded, warns, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		t.Fatalf("loading bundled rules: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("bundled rules produced warnings: %v", warns)
	}
	if len(loaded) == 0 {
		t.Fatal("no bundled rules loaded")
	}
}
