package a2a

import (
	"context"

	"github.com/calbebop/batesian/internal/attack"
)

// A rule that finds nothing has to say which of two things happened: the target
// is an A2A agent and this attack did not work against it, or nothing here is an
// A2A agent at all. The first is a clean result. The second is a target that was
// never tested, and reporting it as clean is how a scan claims coverage it does
// not have.
//
// Rules used to draw that line individually, and drew it differently. Some
// returned nil when their feature gate found nothing, without ever asking
// whether a card was served. Three kept a local "reached" flag set by any
// response that was not a 404, which an unrelated JSON-RPC service satisfies.
// The MCP executors were converged onto one rule for this; these are the A2A
// half of the same work.
//
// The test is deliberately generous: an agent card at either path, or a
// discovered JSON-RPC endpoint. A2A agents exist that serve no card, and agents
// exist whose card is served but whose JSON-RPC transport is not where we look,
// so requiring both would skip real targets.

// cardServed reports whether either card path serves something that parses as an
// agent card. It is the cheapest evidence that a target is an A2A agent, and
// most rules have already made this call for their own reasons.
func cardServed(ctx context.Context, client *attack.HTTPClient, baseURL string) bool {
	for _, path := range []string{cardPathPrimary, cardPathLegacy} {
		if _, _, ok := fetchCard(ctx, client, baseURL+path); ok {
			return true
		}
	}
	return false
}

// notTestableGiven converts "this rule found nothing" into the right answer for
// a rule that has already run endpoint discovery. If the target is an A2A agent
// the empty result stands; if nothing here is one, the rule reports that it
// could not be exercised.
//
// The card is only fetched when discovery came up empty, which is the only case
// where it can change the answer, so the common path costs nothing.
//
// Rules that analyse the agent card do not use this. A card rule with no card
// has nothing to say whether or not the target is an agent by other evidence, so
// those report inconclusive directly.
func notTestableGiven(ctx context.Context, client *attack.HTTPClient, baseURL string, endpointOK bool) error {
	if endpointOK {
		return nil
	}
	if cardServed(ctx, client, baseURL) {
		return nil
	}
	return attack.ErrInconclusive
}
