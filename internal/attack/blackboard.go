package attack

import (
	"context"
	"sync"
)

// ArtifactKind classifies a piece of state discovered or produced during a scan.
// Chained executors publish artifacts of a given kind and consume the kinds they
// depend on, which lets the engine order producers before consumers and lets one
// rule build on another's results (e.g. a discovered capability driving a
// targeted follow-up, or an accepted token driving a downstream access test).
type ArtifactKind string

const (
	// ArtifactToken is a bearer token (real, forged, or replayed) that downstream
	// rules can present to test access. Principal identifies whose token it is.
	ArtifactToken ArtifactKind = "token"
	// ArtifactEndpoint is a confirmed live protocol endpoint (e.g. the resolved
	// MCP JSON-RPC URL or an A2A RPC URL) so consumers need not re-discover it.
	ArtifactEndpoint ArtifactKind = "endpoint"
	// ArtifactCapability is a capability the target advertised (e.g. "prompts",
	// "resources", "push-notifications", "extended-agent-card").
	ArtifactCapability ArtifactKind = "capability"
	// ArtifactTaskID is an A2A task identifier created during a scan.
	ArtifactTaskID ArtifactKind = "task-id"
	// ArtifactContextID is an A2A context identifier created during a scan.
	ArtifactContextID ArtifactKind = "context-id"
	// ArtifactSession is a transport session identifier (e.g. an MCP
	// Mcp-Session-Id) that a downstream rule can present to test whether the
	// session can be borrowed or replayed across principals.
	ArtifactSession ArtifactKind = "session-id"
	// ArtifactAudience is the resource server's expected JWT `aud` value, once
	// known (operator-supplied or discovered via RFC 9728).
	ArtifactAudience ArtifactKind = "audience"
	// ArtifactClient is an OAuth client registered during a scan (e.g. via DCR).
	ArtifactClient ArtifactKind = "registered-client"
)

// Artifact is a single typed datum on the Blackboard.
type Artifact struct {
	// Kind classifies the datum so consumers can query by type.
	Kind ArtifactKind
	// Value is the primary payload (token string, URL, capability name, ID, ...).
	Value string
	// Principal names the identity/tenant this artifact belongs to. Empty means
	// anonymous / the default principal. Multi-principal and multi-tenant rules
	// use this to keep one principal's artifacts distinct from another's.
	Principal string
	// Producer is the rule ID that published the artifact, for provenance.
	Producer string
	// Meta carries optional extra fields (granted scopes, aud, mime type, ...).
	Meta map[string]string
}

// Blackboard is the concurrency-safe shared state for a single scan. Executors
// publish artifacts they discover and read artifacts published by earlier rules.
// Its zero value is not usable; construct it with NewBlackboard.
type Blackboard struct {
	mu        sync.RWMutex
	artifacts []Artifact
}

// NewBlackboard returns an empty, ready-to-use Blackboard.
func NewBlackboard() *Blackboard {
	return &Blackboard{}
}

// Publish records an artifact on the blackboard.
func (b *Blackboard) Publish(a Artifact) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.artifacts = append(b.artifacts, a)
}

// ByKind returns all artifacts of the given kind, in publication order.
func (b *Blackboard) ByKind(kind ArtifactKind) []Artifact {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var out []Artifact
	for _, a := range b.artifacts {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

// First returns the first artifact of the given kind, if any.
func (b *Blackboard) First(kind ArtifactKind) (Artifact, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, a := range b.artifacts {
		if a.Kind == kind {
			return a, true
		}
	}
	return Artifact{}, false
}

// Find returns all artifacts matching pred, in publication order. It lets
// consumers filter by principal, producer, or Meta beyond a simple kind lookup.
func (b *Blackboard) Find(pred func(Artifact) bool) []Artifact {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var out []Artifact
	for _, a := range b.artifacts {
		if pred(a) {
			out = append(out, a)
		}
	}
	return out
}

// All returns a copy of every artifact on the blackboard, in publication order.
func (b *Blackboard) All() []Artifact {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Artifact, len(b.artifacts))
	copy(out, b.artifacts)
	return out
}

// ChainExecutor is the opt-in interface for rules that participate in stateful
// multi-step chaining. The engine calls ExecuteChained (passing the shared
// Blackboard) when an executor implements this interface, and falls back to the
// plain Executor.Execute otherwise. Existing single-shot rules are unaffected.
//
// A ChainExecutor must tolerate an empty or partial blackboard: if the artifacts
// it needs were not produced (e.g. the producing rule was filtered out, or the
// target lacked the precondition), it should return no findings rather than an
// error, consistent with the project's clean-skip convention.
type ChainExecutor interface {
	Executor
	ExecuteChained(ctx context.Context, target string, opts Options, bb *Blackboard) ([]Finding, error)
}

// Dependencies is the opt-in interface an executor implements to declare the
// artifact kinds it produces and consumes. The engine uses these declarations to
// order execution so that producers of a kind run before its consumers. An
// executor that does not implement Dependencies is treated as having no
// declared dependencies and keeps its original position in the run order.
type Dependencies interface {
	// Produces lists the artifact kinds this executor may publish.
	Produces() []ArtifactKind
	// Requires lists the artifact kinds this executor consumes from upstream.
	Requires() []ArtifactKind
}

// ChainStep is one hop in a multi-step attack's provenance trail, attached to a
// Finding so chain-of-custody and auditability are visible in output.
type ChainStep struct {
	// Hop is the 1-based position of this step in the chain.
	Hop int
	// Principal is the identity/tenant that performed the step (empty = default).
	Principal string
	// Action describes what was attempted (e.g. "authenticate as tenant A").
	Action string
	// Outcome describes the result (e.g. "token issued", "read of tenant B granted").
	Outcome string
}
