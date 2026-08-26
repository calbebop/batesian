// Package engine orchestrates rule loading and attack execution for the scan command.
// It imports both the rules and attack packages, sitting above both in the dependency graph.
package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	attackpkg "github.com/calbebop/batesian/internal/attack"
	// Blank imports run each executor package's init(), which registers its
	// attack types with the attack registry. Resolution then happens by
	// lookup rather than a central switch statement.
	_ "github.com/calbebop/batesian/internal/attack/a2a"
	_ "github.com/calbebop/batesian/internal/attack/mcp"
	"github.com/calbebop/batesian/internal/rules"
	"github.com/calbebop/batesian/internal/severity"
)

// RunResult holds the findings and any error from executing a single rule.
type RunResult struct {
	Rule     *rules.Rule
	Findings []attackpkg.Finding
	Err      error
	Skipped  bool
	SkipMsg  string
}

// Engine executes rules against a target.
type Engine struct {
	opts attackpkg.Options
}

// New creates an Engine with the given execution options. The engine owns
// one discovery cache per scan and injects it into the options it hands to
// executors, so endpoint resolution happens once per target rather than once
// per rule.
func New(opts attackpkg.Options) *Engine {
	if opts.Discovery == nil {
		opts.Discovery = attackpkg.NewDiscoveryCache()
	}
	return &Engine{opts: opts}
}

// planEntry pairs a rule with its resolved executor (nil when the attack type
// has no registered executor, in which case the rule is skipped).
type planEntry struct {
	rule     *rules.Rule
	executor attackpkg.Executor
}

// Run executes a slice of rules against target and returns all results.
//
// Rules are resolved to executors, ordered so that producers of an artifact kind
// run before its consumers (see orderPlan), then executed in that order against a
// single shared Blackboard. Executors that implement attackpkg.ChainExecutor read
// and write that blackboard so later rules can build on earlier findings; plain
// executors are unaffected. Errors from individual rules are captured in
// RunResult.Err rather than aborting the entire scan.
func (e *Engine) Run(ctx context.Context, target string, rs []*rules.Rule) []RunResult {
	plan := make([]planEntry, 0, len(rs))
	for _, r := range rs {
		executor, err := resolveExecutor(r)
		if err != nil {
			// Keep a nil-executor entry so the rule still surfaces as Skipped,
			// preserving its position in the run order.
			plan = append(plan, planEntry{rule: r})
			continue
		}
		plan = append(plan, planEntry{rule: r, executor: executor})
	}

	plan = orderPlan(plan)

	bb := attackpkg.NewBlackboard()
	results := make([]RunResult, 0, len(plan))
	for _, entry := range plan {
		results = append(results, e.runOne(ctx, target, entry, bb))
	}
	return results
}

// runOne executes a single plan entry and returns its RunResult.
// A panic inside any executor is caught and surfaced as RunResult.Err so that
// the rest of the scan can continue rather than crashing the process.
func (e *Engine) runOne(ctx context.Context, target string, entry planEntry, bb *attackpkg.Blackboard) (result RunResult) {
	r := entry.rule

	if entry.executor == nil {
		return RunResult{
			Rule:    r,
			Skipped: true,
			SkipMsg: fmt.Sprintf("no executor for attack type %q", r.Attack.Type),
		}
	}

	// Bail out immediately if the scan context was already cancelled.
	if ctx.Err() != nil {
		return RunResult{
			Rule:    r,
			Skipped: true,
			SkipMsg: "context cancelled before executor started",
		}
	}

	defer func() {
		if p := recover(); p != nil {
			result = RunResult{
				Rule: r,
				Err:  fmt.Errorf("executor panicked: %v", p),
			}
		}
	}()

	// In a dry run, label every request this rule records so the plan groups by rule.
	if e.opts.Recorder != nil {
		e.opts.Recorder.SetCurrentRule(r.ID)
	}

	var findings []attackpkg.Finding
	var err error
	if chained, ok := entry.executor.(attackpkg.ChainExecutor); ok {
		findings, err = chained.ExecuteChained(ctx, target, e.opts, bb)
	} else {
		findings, err = entry.executor.Execute(ctx, target, e.opts)
	}
	// A rule that could not reach a testable endpoint is recorded as skipped, not
	// as a (misleading) clean result and not as an error.
	if errors.Is(err, attackpkg.ErrInconclusive) {
		// Executors may wrap ErrInconclusive with the reason the rule could not
		// run. Surface that detail rather than discarding it: "not tested because
		// your server speaks MCP 2026-07-28" is actionable, while a bare "could
		// not reach a testable endpoint" invites the operator to assume a network
		// problem.
		//
		// When a reason is supplied it REPLACES the generic sentence instead of
		// being appended to it. Most reasons describe a target that was reached
		// and then could not be assessed (an unsupported protocol revision, an
		// absent agent card, a probe that established nothing after a successful
		// handshake), so prefixing them with a reachability claim produced a
		// message that contradicted itself.
		msg := "could not reach a testable endpoint"
		if detail := inconclusiveDetail(err); detail != "" {
			msg = "not tested: " + detail
		}
		return RunResult{
			Rule:    r,
			Skipped: true,
			SkipMsg: msg,
		}
	}
	return RunResult{
		Rule:     r,
		Findings: findings,
		Err:      err,
	}
}

// orderPlan stably reorders entries so that any executor producing an artifact
// kind runs before any executor that requires that kind. It uses Kahn's
// algorithm over the producer->consumer edges implied by the executors'
// attackpkg.Dependencies declarations. Entries that declare no dependencies keep
// their original relative order. If a dependency cycle exists, the remaining
// entries are appended in their original order (the chained executors tolerate a
// partial blackboard, so a cycle degrades gracefully rather than deadlocking).
func orderPlan(plan []planEntry) []planEntry {
	n := len(plan)
	if n < 2 {
		return plan
	}

	produces := make([]map[attackpkg.ArtifactKind]bool, n)
	requires := make([]map[attackpkg.ArtifactKind]bool, n)
	hasDeps := false
	for i, entry := range plan {
		produces[i] = map[attackpkg.ArtifactKind]bool{}
		requires[i] = map[attackpkg.ArtifactKind]bool{}
		dep, ok := entry.executor.(attackpkg.Dependencies)
		if !ok {
			continue
		}
		for _, k := range dep.Produces() {
			produces[i][k] = true
		}
		for _, k := range dep.Requires() {
			requires[i][k] = true
			hasDeps = true
		}
	}
	// Fast path: nothing declares a requirement, so original order stands.
	if !hasDeps {
		return plan
	}

	// Build edges producer->consumer and in-degrees.
	indegree := make([]int, n)
	adj := make([][]int, n)
	for j := 0; j < n; j++ {
		for k := range requires[j] {
			for i := 0; i < n; i++ {
				if i != j && produces[i][k] {
					adj[i] = append(adj[i], j)
					indegree[j]++
				}
			}
		}
	}

	ordered := make([]planEntry, 0, n)
	done := make([]bool, n)
	for len(ordered) < n {
		// Pick the lowest-index ready node for stable ordering.
		next := -1
		for i := 0; i < n; i++ {
			if !done[i] && indegree[i] == 0 {
				next = i
				break
			}
		}
		if next == -1 {
			// Cycle: append all remaining nodes in original order.
			for i := 0; i < n; i++ {
				if !done[i] {
					ordered = append(ordered, plan[i])
					done[i] = true
				}
			}
			break
		}
		ordered = append(ordered, plan[next])
		done[next] = true
		indegree[next] = -1 // remove from future consideration
		for _, j := range adj[next] {
			if !done[j] {
				indegree[j]--
			}
		}
	}
	return ordered
}

// resolveExecutor maps a rule's attack type to the corresponding Executor via
// the attack registry. It converts rules.Rule into attack.RuleContext to avoid
// an import cycle between the rules and attack packages.
func resolveExecutor(r *rules.Rule) (attackpkg.Executor, error) {
	rc := attackpkg.RuleContext{
		ID:          r.ID,
		Name:        r.Info.Name,
		Severity:    r.Info.Severity,
		Remediation: r.Remediation,
	}
	ctor, ok := attackpkg.Resolve(r.Attack.Type)
	if !ok {
		return nil, fmt.Errorf("unknown attack type %q", r.Attack.Type)
	}
	return ctor(rc), nil
}

// TotalFindings counts the total number of findings across all results.
func TotalFindings(results []RunResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Findings)
	}
	return n
}

// FindingsBySeverity groups findings by severity level, folded to canonical
// (lowercase) spelling. The JSON summary buckets it by lowercase key, while the
// table printer canonicalizes on its own end, so bucketing by raw f.Severity left
// a capitalized severity ("High") in its own bucket and the summary count
// disagreeing with the findings list. Canonical is idempotent, so a finding
// already carrying a lowercase severity is unchanged.
func FindingsBySeverity(results []RunResult) map[string][]attackpkg.Finding {
	out := make(map[string][]attackpkg.Finding)
	for _, r := range results {
		for _, f := range r.Findings {
			out[severity.Canonical(f.Severity)] = append(out[severity.Canonical(f.Severity)], f)
		}
	}
	return out
}

// inconclusiveDetail returns the reason an executor attached when wrapping
// ErrInconclusive, or "" when it wrapped nothing. Executors wrap with
// fmt.Errorf("%w: <reason>", attack.ErrInconclusive), so the reason is whatever
// follows the sentinel's own message.
func inconclusiveDetail(err error) string {
	full := err.Error()
	base := attackpkg.ErrInconclusive.Error()
	if !strings.HasPrefix(full, base) {
		return ""
	}
	return strings.TrimPrefix(strings.TrimPrefix(full, base), ": ")
}
