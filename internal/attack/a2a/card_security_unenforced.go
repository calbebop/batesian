package a2a

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// CardSecurityUnenforcedExecutor tests whether an A2A server enforces the
// authentication its own AgentCard advertises (rule a2a-card-security-unenforced-001).
//
// The AgentCard is a machine-readable contract. Its securitySchemes plus a
// requirements list (named "security" in v0.3 cards, "securityRequirements" in
// v1.0 proto-JSON cards) declare which authentication a caller MUST present. When
// the card declares a non-empty requirement with no anonymous alternative, yet
// the server answers an unauthenticated core request with a result, the agent
// violates its own published security contract - broad unauthenticated access to
// an agent that told clients it was protected.
//
// This is the case nothing else covers: a2a-task-idor-001 keys off whether
// anonymous creation is rejected and suppresses its finding when the server has
// no auth at all, so a wide-open agent goes unflagged today. This rule flags it
// precisely when the card promised auth (an attributable regression). It is
// distinct from a2a-extcard-unauth-001 (the extended-card endpoint) and
// a2a-card-trust-001 / a2a-jws-algconf-001 (card signatures).
//
// SAFETY: the read probe is non-mutating (tasks/get on a random non-existent id).
// The confirmation write creates a single throwaway probe task, the same footprint
// a2a-task-idor-001 already has.
type CardSecurityUnenforcedExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-card-security-unenforced", func(rc attack.RuleContext) attack.Executor {
		return NewCardSecurityUnenforcedExecutor(rc)
	})
}

func NewCardSecurityUnenforcedExecutor(r attack.RuleContext) *CardSecurityUnenforcedExecutor {
	return &CardSecurityUnenforcedExecutor{rule: r}
}

// probeOutcome classifies an unauthenticated core request.
type probeOutcome int

const (
	probeAuthRejected    probeOutcome = iota // HTTP 401/403 or an auth-flavored error: auth enforced
	probeProcessedError                      // reached the handler, returned a non-auth application error
	probeProcessedResult                     // reached the handler, returned a success result envelope
)

func (e *CardSecurityUnenforcedExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// Every request this rule makes is anonymous. The agent card is the PUBLIC
	// contract an unauthenticated caller reads, and the probes must present no
	// credentials, so injecting opts.Token anywhere would misrepresent what an
	// anonymous client actually sees.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// Fetch the card. Without it there is no declared contract to test against.
	cardBody, ok := fetchAgentCardBody(ctx, client, vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}
	card, ok := parseCard(cardBody)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	// Only proceed when the card declares required auth with no anonymous option.
	schemes, required := declaredAuthRequirement(card)
	if !required {
		return nil, nil
	}

	// Resolve the JSON-RPC endpoint to probe. The card requires auth but we cannot
	// reach a testable endpoint, so the contract cannot be exercised here.
	endpoint, ok := resolveA2AEndpoint(ctx, client, vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	// Step 1 (non-mutating): can an unauthenticated read even reach the handler?
	// A read of a random non-existent id cannot return a task, so this only tells
	// us whether the read path rejects at the auth layer (evidence, not verdict).
	readReachable := e.readTask(ctx, client, endpoint, "batesian-missing-"+vars.RandID, vars.RandID) != probeAuthRejected

	// Step 2 (definitive): unauthenticated create. A returned task proves a core
	// write executed with no credentials despite the card requiring them.
	createOutcome, createdTaskID := e.createProbe(ctx, client, endpoint, vars.RandID)
	if createOutcome != probeProcessedResult {
		// No unauthenticated request was processed into a success result: either the
		// server enforces auth (rejected) or only returned application errors. Do not
		// claim a violation without a positive, unambiguous result envelope.
		return nil, nil
	}

	// Strengthen: read the just-created task back with no credentials. If that also
	// returns the task, both the write and the read paths ignore the declared auth.
	readBack := createdTaskID != "" && e.readTask(ctx, client, endpoint, createdTaskID, vars.RandID) == probeProcessedResult

	return []attack.Finding{e.finding(endpoint, schemes, createdTaskID, readReachable, readBack)}, nil
}

// readTask issues an unauthenticated tasks/get for taskID (v1.0 GetTask then v0.3
// tasks/get) and classifies the strongest outcome seen.
func (e *CardSecurityUnenforcedExecutor) readTask(ctx context.Context, c *attack.HTTPClient, endpoint, taskID, randID string) probeOutcome {
	shapes := []struct {
		method  string
		headers map[string]string
	}{
		{"GetTask", map[string]string{"A2A-Version": "1.0"}},
		{"tasks/get", nil},
	}
	outcome := probeAuthRejected
	for _, s := range shapes {
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-cardsec-get-" + randID,
			"method":  s.method,
			"params":  map[string]interface{}{"id": taskID, "historyLength": 1},
		})
		if err != nil {
			continue
		}
		if o := classifyProbe(resp); o > outcome {
			outcome = o
		}
	}
	return outcome
}

// createProbe issues an unauthenticated message/send (v1.0 SendMessage then v0.3
// message/send) and reports whether a task was created without credentials.
func (e *CardSecurityUnenforcedExecutor) createProbe(ctx context.Context, c *attack.HTTPClient, endpoint, randID string) (probeOutcome, string) {
	shapes := []struct {
		method  string
		headers map[string]string
		message map[string]interface{}
	}{
		{"SendMessage", map[string]string{"A2A-Version": "1.0"}, map[string]interface{}{
			"role":      1,
			"parts":     []interface{}{map[string]string{"text": "batesian card-security probe " + randID}},
			"messageId": "batesian-cardsec-" + randID,
		}},
		{"message/send", nil, map[string]interface{}{
			"role":      "user",
			"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian card-security probe " + randID}},
			"messageId": "batesian-cardsec-" + randID,
		}},
	}
	outcome := probeAuthRejected
	for _, s := range shapes {
		resp, err := c.POST(ctx, endpoint, s.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-cardsec-send-" + randID,
			"method":  s.method,
			"params":  map[string]interface{}{"message": s.message},
		})
		if err != nil {
			continue
		}
		o := classifyProbe(resp)
		if o == probeProcessedResult {
			taskID, _ := extractTaskContext(resp.Body)
			if taskID == "" {
				// A result envelope with no task id does not confirm a task was
				// actually created; do not promote to a confirmed processed result.
				o = probeProcessedError
			} else {
				return probeProcessedResult, taskID
			}
		}
		if o > outcome {
			outcome = o
		}
	}
	return outcome, ""
}

// classifyProbe maps an unauthenticated response to a probeOutcome. An auth
// rejection (HTTP 401/403 or auth-flavored error) means auth is enforced; an
// HTTP 200 with a JSON-RPC result envelope means the handler processed the
// anonymous request and returned data; anything else in between (HTTP 200 with a
// non-auth application error) means the handler was reached but errored.
func classifyProbe(resp *attack.Response) probeOutcome {
	if isA2AAuthRejection(resp) {
		return probeAuthRejected
	}
	if resp.IsAccepted() {
		return probeProcessedResult
	}
	if resp.IsSuccess() {
		return probeProcessedError
	}
	return probeAuthRejected
}

func (e *CardSecurityUnenforcedExecutor) finding(endpoint string, schemes []string, taskID string, readReachable, readBack bool) attack.Finding {
	schemeList := strings.Join(schemes, ", ")
	readLine := "unauthenticated read (tasks/get) of the created task: not confirmed"
	if readBack {
		readLine = "unauthenticated read (tasks/get) of the created task: task returned"
	} else if readReachable {
		readLine = "unauthenticated read (tasks/get) path: reachable (not rejected at the auth layer)"
	}
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A agent card declares required authentication but the endpoint serves unauthenticated requests",
		Description: fmt.Sprintf(
			"The agent card declares a security requirement (scheme(s): %s) that a caller MUST satisfy, "+
				"yet an unauthenticated message/send at %s created task %s and returned its result with no "+
				"credentials presented. The card is the agent's published security contract; the server does "+
				"not enforce it, so any anonymous caller has the access the card says requires "+
				"authentication.", schemeList, endpoint, taskID),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ncard-declared security scheme(s): %s\nunauthenticated message/send: accepted (created task %s)\n%s",
			endpoint, schemeList, taskID, readLine),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

// fetchAgentCardBody returns the raw card body from the primary (v1.0) path,
// falling back to the legacy (v0.3) path.
func fetchAgentCardBody(ctx context.Context, client *attack.HTTPClient, baseURL string) ([]byte, bool) {
	if body, _, ok := fetchCard(ctx, client, baseURL+cardPathPrimary); ok {
		return body, true
	}
	if body, _, ok := fetchCard(ctx, client, baseURL+cardPathLegacy); ok {
		return body, true
	}
	return nil, false
}

// declaredAuthRequirement reports the distinct scheme names a card requires, and
// whether authentication is required with no anonymous alternative. It reads the
// v1.0 securityRequirements list first, then the v0.3 security list. Per OpenAPI
// semantics an empty requirement object ({}) in the list explicitly permits
// anonymous access, so its presence means auth is NOT required.
func declaredAuthRequirement(card map[string]interface{}) (schemes []string, required bool) {
	list := cardSecurityList(card)
	if len(list) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	for _, item := range list {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, false // malformed requirement entry: do not assert a violation
		}
		if len(obj) == 0 {
			return nil, false // empty requirement object: anonymous access is allowed
		}
		for name := range obj {
			if !seen[name] {
				seen[name] = true
				schemes = append(schemes, name)
			}
		}
	}
	sort.Strings(schemes)
	return schemes, true
}

// cardSecurityList returns the requirements list, preferring the v1.0
// securityRequirements field and falling back to the v0.3 security field.
func cardSecurityList(card map[string]interface{}) []interface{} {
	if v, ok := card["securityRequirements"].([]interface{}); ok && len(v) > 0 {
		return v
	}
	if v, ok := card["security"].([]interface{}); ok {
		return v
	}
	return nil
}
