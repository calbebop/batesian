package engine_test

import (
	"context"
	"sync"
	"testing"

	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/engine"
	"github.com/calbebop/batesian/internal/rules"
)

// runLog records the order in which fake executors run, shared across the fakes
// registered for a single test. Guarded because executors may run on any
// goroutine in principle (the engine runs them serially today, but the lock
// keeps the test correct if that changes).
type runLog struct {
	mu    sync.Mutex
	order []string
}

func (l *runLog) record(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.order = append(l.order, id)
}

func (l *runLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.order))
	copy(out, l.order)
	return out
}

// log is the package-level sink the registered fakes write to. Tests reset it
// at the start. Because executor registration is process-global and happens in
// init(), the fakes read this shared variable rather than capturing per-test
// state.
var log = &runLog{}

// --- fake plain executor (no chaining, no deps) ---

type plainFake struct{ rc attack.RuleContext }

func (f plainFake) Execute(_ context.Context, _ string, _ attack.Options) ([]attack.Finding, error) {
	log.record(f.rc.ID)
	return nil, nil
}

// --- fake producer: publishes a token artifact (chained) ---

type producerFake struct{ rc attack.RuleContext }

func (f producerFake) Execute(_ context.Context, _ string, _ attack.Options) ([]attack.Finding, error) {
	return nil, nil
}

func (f producerFake) ExecuteChained(_ context.Context, _ string, _ attack.Options, bb *attack.Blackboard) ([]attack.Finding, error) {
	log.record(f.rc.ID)
	bb.Publish(attack.Artifact{
		Kind:      attack.ArtifactToken,
		Value:     "forged-token-xyz",
		Principal: "tenant-a",
		Producer:  f.rc.ID,
	})
	return nil, nil
}

func (f producerFake) Produces() []attack.ArtifactKind {
	return []attack.ArtifactKind{attack.ArtifactToken}
}
func (f producerFake) Requires() []attack.ArtifactKind { return nil }

// --- fake consumer: requires a token artifact and reports a chained finding ---

type consumerFake struct{ rc attack.RuleContext }

func (f consumerFake) Execute(_ context.Context, _ string, _ attack.Options) ([]attack.Finding, error) {
	return nil, nil
}

func (f consumerFake) ExecuteChained(_ context.Context, _ string, _ attack.Options, bb *attack.Blackboard) ([]attack.Finding, error) {
	log.record(f.rc.ID)
	tok, ok := bb.First(attack.ArtifactToken)
	if !ok {
		// Tolerate a missing artifact per the ChainExecutor contract.
		return nil, nil
	}
	return []attack.Finding{{
		RuleID:     f.rc.ID,
		RuleName:   f.rc.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "downstream access via upstream token",
		Evidence:   "consumed token: " + tok.Value,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: tok.Principal, Action: "obtain token", Outcome: "token published"},
			{Hop: 2, Principal: tok.Principal, Action: "replay token downstream", Outcome: "access granted"},
		},
	}}, nil
}

func (f consumerFake) Produces() []attack.ArtifactKind { return nil }
func (f consumerFake) Requires() []attack.ArtifactKind {
	return []attack.ArtifactKind{attack.ArtifactToken}
}

func init() {
	attack.Register("test-plain", func(rc attack.RuleContext) attack.Executor { return plainFake{rc} })
	attack.Register("test-producer", func(rc attack.RuleContext) attack.Executor { return producerFake{rc} })
	attack.Register("test-consumer", func(rc attack.RuleContext) attack.Executor { return consumerFake{rc} })
}

func ruleFor(id, attackType string) *rules.Rule {
	return &rules.Rule{
		ID:     id,
		Info:   rules.RuleInfo{Name: id, Severity: "high"},
		Attack: rules.AttackBlock{Protocol: "mcp", Type: attackType},
	}
}

// TestChain_ConsumerRunsAfterProducer asserts the engine orders a consumer after
// its producer even when the rules are supplied consumer-first, and that the
// consumer reads the artifact the producer published to the shared blackboard.
func TestChain_ConsumerRunsAfterProducer(t *testing.T) {
	log = &runLog{}
	eng := engine.New(attack.Options{TimeoutSeconds: 1})

	// Supplied consumer-first to prove ordering is by dependency, not input order.
	rs := []*rules.Rule{
		ruleFor("consumer-001", "test-consumer"),
		ruleFor("producer-001", "test-producer"),
	}
	results := eng.Run(context.Background(), "http://127.0.0.1:1", rs)

	order := log.snapshot()
	if len(order) != 2 || order[0] != "producer-001" || order[1] != "consumer-001" {
		t.Fatalf("expected producer before consumer, got run order %v", order)
	}

	// The consumer should have produced a chained finding from the published token.
	var chained *engine.RunResult
	for i := range results {
		if results[i].Rule.ID == "consumer-001" {
			chained = &results[i]
		}
	}
	if chained == nil || len(chained.Findings) != 1 {
		t.Fatalf("expected 1 finding from consumer, got %+v", chained)
	}
	f := chained.Findings[0]
	if f.Evidence != "consumed token: forged-token-xyz" {
		t.Errorf("consumer did not read the producer's artifact: %q", f.Evidence)
	}
	if len(f.Chain) != 2 || f.Chain[1].Outcome != "access granted" {
		t.Errorf("expected 2-hop provenance chain, got %+v", f.Chain)
	}
}

// TestChain_PlainExecutorStillRuns asserts that a plain (non-chained, no-deps)
// executor is dispatched via Execute and keeps its input ordering relative to
// other dependency-free rules.
func TestChain_PlainExecutorStillRuns(t *testing.T) {
	log = &runLog{}
	eng := engine.New(attack.Options{TimeoutSeconds: 1})

	rs := []*rules.Rule{
		ruleFor("plain-a", "test-plain"),
		ruleFor("plain-b", "test-plain"),
	}
	results := eng.Run(context.Background(), "http://127.0.0.1:1", rs)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	order := log.snapshot()
	if len(order) != 2 || order[0] != "plain-a" || order[1] != "plain-b" {
		t.Fatalf("dependency-free rules should keep input order, got %v", order)
	}
}

// TestChain_ConsumerToleratesMissingArtifact asserts that when no producer is in
// the run set, the consumer runs and returns no findings rather than erroring.
func TestChain_ConsumerToleratesMissingArtifact(t *testing.T) {
	log = &runLog{}
	eng := engine.New(attack.Options{TimeoutSeconds: 1})

	rs := []*rules.Rule{ruleFor("consumer-only", "test-consumer")}
	results := eng.Run(context.Background(), "http://127.0.0.1:1", rs)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Errorf("consumer with no upstream artifact should not error: %v", results[0].Err)
	}
	if len(results[0].Findings) != 0 {
		t.Errorf("consumer with no upstream artifact should report nothing, got %d findings", len(results[0].Findings))
	}
}
