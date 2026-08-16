package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	batesian "github.com/calbebop/batesian"
	"github.com/calbebop/batesian/internal/rules"
	"github.com/calbebop/batesian/internal/severity"
)

// TestSeverityLiteralsWithinDeclaredSeverity pins every severity literal an
// executor hardcodes to at or below the severity its rule YAML declares.
//
// --severity filters on the YAML value while findings carry the executor's own,
// so a literal above the YAML makes the filter silently skip a rule that can
// emit at the filtered level: an operator running --severity critical missed
// every critical finding from five rules that declared high (and one that
// declared critical while emitting only high/medium, the reverse lie). Nothing
// connected the two sides, so the drift was invisible to CI.
//
// Findings graded BELOW the YAML are fine and intentional: several rules
// impact-grade downward (a resources list at high under a critical headline), so
// the pinned direction is one-way. Severities chosen at runtime (escalations
// from response content, rc.Severity flowing from the YAML itself) are not
// literals and are out of this scan's reach by construction.
//
// The rule-to-executor mapping comes from each file's own attack.Register call,
// not from a naming convention, so a renamed file cannot detach the check.
func TestSeverityLiteralsWithinDeclaredSeverity(t *testing.T) {
	loaded, _, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		t.Fatalf("loading bundled rules: %v", err)
	}

	typeFile, fileLiterals := scanExecutors(t)

	for _, r := range loaded {
		src, ok := typeFile[r.Attack.Type]
		if !ok {
			t.Errorf("no executor registers attack type %q (rule %s); the rule can never run", r.Attack.Type, r.ID)
			continue
		}
		declared := severity.Rank(r.Info.Severity)
		for _, lit := range fileLiterals[src] {
			if rank := severity.Rank(lit); rank > declared {
				t.Errorf("%s declares severity %q but its executor (%s) hardcodes a %q finding; "+
					"--severity filtering reads the YAML, so filtering at %q skips this rule entirely",
					r.ID, r.Info.Severity, src, lit, r.Info.Severity)
			}
		}
	}
}

// scanExecutors walks the two executor packages and returns, per attack type,
// the file that registers it, and per file, the distinct severity string
// literals assigned to a Severity/severity field.
func scanExecutors(t *testing.T) (map[string]string, map[string][]string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	registerRe := regexp.MustCompile(`attack\.Register\("([^"]+)"`)
	// Both spellings the executors use: the Finding field (Severity:) and
	// per-probe tables that feed it (severity:). A literal that is not a
	// canonical severity (Rank 0, unknown strings included) cannot exceed any
	// declared value, so non-severity collisions are harmless.
	literalRe := regexp.MustCompile(`[Ss]everity:\s*"([A-Za-z]+)"`)

	typeFile := map[string]string{}
	fileLiterals := map[string][]string{}
	for _, pkg := range []string{"a2a", "mcp"} {
		dir := filepath.Join(repoRoot, "internal", "attack", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(pkg, name)
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, m := range registerRe.FindAllSubmatch(b, -1) {
				if prev, dup := typeFile[string(m[1])]; dup {
					t.Errorf("attack type %q is registered in both %s and %s", m[1], prev, path)
				}
				typeFile[string(m[1])] = path
			}
			seen := map[string]bool{}
			for _, m := range literalRe.FindAllSubmatch(b, -1) {
				seen[string(m[1])] = true
			}
			for lit := range seen {
				fileLiterals[path] = append(fileLiterals[path], lit)
			}
		}
	}
	return typeFile, fileLiterals
}
