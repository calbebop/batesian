package a2a

import (
	"context"
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskEnumerationExecutor tests whether one authenticated principal can enumerate
// another's tasks through ListTasks (rule a2a-task-enumeration-001).
//
// The specification is explicit twice over. Section 3.1.4, on ListTasks itself:
// "Implementations MUST implement appropriate authorization scoping to ensure clients
// can only access authorized tasks." Section 13.1: "Servers MUST return only tasks
// visible to the authenticated client."
//
// This is a different surface from the rules that already exist, not a second look at
// the same one:
//
//   - a2a-multitenant-isolation-001 reads a task BY ID, so it only proves a caller
//     who already knows an identifier can fetch it. Enumeration needs no prior
//     knowledge, which is what makes it worse: an attacker with one valid credential
//     learns every task id on the server and then has everything the read rules need.
//   - a2a-task-idor-001 probes the REST list paths ANONYMOUSLY. A server that
//     correctly requires a credential passes that and can still hand every tenant's
//     tasks to any authenticated caller.
//   - The listing endpoint is separate code from the per-task fetch, so a server can
//     scope one and not the other, and commonly does: the fetch has an obvious owner
//     to compare against while the list has to be filtered.
//
// Currency: ListTasks is a v1.0 JSON-RPC method. The v0.3 revision defines
// tasks/get, tasks/cancel, tasks/resubscribe and the push-notification-config
// methods, and no list method at all, so a v0.3-only agent answers -32601 and the
// rule reports itself not applicable. The v0.3 REST binding's list path is covered
// anonymously by a2a-task-idor-001; the authenticated cross-principal case on that
// binding is not probed here, deliberately, because the prefix belongs to the
// deployment and guessing it is how earlier rules came to POST at paths that never
// existed.
type TaskEnumerationExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-task-enumeration", func(rc attack.RuleContext) attack.Executor {
		return NewTaskEnumerationExecutor(rc)
	})
}

func NewTaskEnumerationExecutor(r attack.RuleContext) *TaskEnumerationExecutor {
	return &TaskEnumerationExecutor{rule: r}
}

func (e *TaskEnumerationExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	// Two distinct identities are the premise: the question is whether B sees A's
	// task, which cannot be asked with one principal. See twoPrincipals.
	a, b, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
	}

	vars := attack.NewVars(target, opts.OOBListenerURL)
	endpoint, ok := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	if !ok {
		return nil, attack.ErrInconclusive
	}

	clientA := principalClient(opts, vars, a)
	clientB := principalClient(opts, vars, b)
	unauthClient := attack.NewUnauthHTTPClient(opts, attack.NewVars(target, opts.OOBListenerURL))

	// Step 1: A owns a task. Without one there is nothing for B to find, and a clean
	// result would claim the listing is scoped having never given it anything to leak.
	taskID, _, _, obs := e.createTask(ctx, clientA, endpoint, a, vars.RandID)
	if taskID == "" {
		return nil, obs.err()
	}

	// Step 2: is the listing implemented at all? Asked as A, who owns a task and so
	// should see at least one, which also confirms the surface works before any
	// conclusion is drawn about B.
	ownList, ownOutcome := e.listTasks(ctx, clientA, endpoint, a.Headers, vars.RandID)
	switch ownOutcome {
	case listAbsent:
		// No list method here. Nothing to scope, and nothing wrong: the same call the
		// OAuth-gated rules make for a server exposing no OAuth.
		return nil, nil
	case listRefused:
		return nil, fmt.Errorf("%w: ListTasks at %s was refused for the task's own owner (%s), "+
			"so whether the listing is scoped to the caller could not be established",
			attack.ErrInconclusive, endpoint, a.Name)
	}
	if !containsTaskID(ownList, taskID) {
		// The owner cannot see their own task, so this listing does not enumerate what
		// the rule assumes it enumerates and B seeing nothing would prove nothing.
		return nil, fmt.Errorf("%w: ListTasks at %s did not return principal %s's own task %s, "+
			"so the listing does not enumerate the tasks this rule compares against",
			attack.ErrInconclusive, endpoint, a.Name, taskID)
	}

	// Step 3: open-server discriminator. If an UNAUTHENTICATED list returns A's task,
	// the server enforces no authorization on this surface at all. That is a2a-task-
	// idor-001's finding, not a scoping failure between two valid principals, and
	// reporting it here would double-count one defect as two.
	if anonList, anonOutcome := e.listTasks(ctx, unauthClient, endpoint, nil, vars.RandID); anonOutcome == listOK &&
		containsTaskID(anonList, taskID) {
		return nil, nil
	}

	// Step 4: B lists. A's task appearing in it is the finding: B is authenticated,
	// holds no claim to A's task, and was handed its identifier anyway.
	otherList, otherOutcome := e.listTasks(ctx, clientB, endpoint, b.Headers, vars.RandID)
	if otherOutcome != listOK {
		// B cannot list at all, which is one legitimate way to scope the surface.
		return nil, nil
	}
	if !containsTaskID(otherList, taskID) {
		return nil, nil // scoped: B's listing does not include A's task
	}

	return []attack.Finding{e.finding(endpoint, a, b, taskID, otherList)}, nil
}

// listOutcome distinguishes the three answers a listing attempt can give, because
// they mean different things: absent is not applicable, refused is untested, and only
// an answered list can be judged.
type listOutcome int

const (
	listOK listOutcome = iota
	// listAbsent is -32601 on every spelling tried: the method is not implemented.
	listAbsent
	// listRefused is any other failure, including an authorization refusal.
	listRefused
)

// listTasks asks for the caller's tasks and returns the identifiers it received.
//
// pageSize is set high enough that a scoped server has no pagination excuse for
// omitting a task, and historyLength is zero because this rule needs identifiers
// rather than conversation content: enumerating ids is the failure, and pulling
// another tenant's message history to prove it would be gratuitous.
func (e *TaskEnumerationExecutor) listTasks(ctx context.Context, c *attack.HTTPClient, endpoint string,
	extraHeaders map[string]string, randID string) ([]string, listOutcome) {
	attempts := []struct {
		method  string
		headers map[string]string
	}{
		{"ListTasks", withV1Version(extraHeaders)},
		// v0.3 defines no list method, so this only reaches an implementation that
		// chose the slash spelling anyway. It costs one request on a path that would
		// otherwise report the surface absent.
		{"tasks/list", extraHeaders},
	}

	absentEverywhere := true
	for _, at := range attempts {
		resp, err := c.POST(ctx, endpoint, at.headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-enum-" + randID,
			"method":  at.method,
			"params":  map[string]interface{}{"pageSize": 100, "historyLength": 0},
		})
		if err != nil {
			absentEverywhere = false
			continue
		}
		if resp.IsAccepted() {
			return listedTaskIDs(resp.Body), listOK
		}
		if code, hasErr := jsonRPCErrorCode(resp.Body); !hasErr || code != jsonRPCMethodNotFound {
			// Something other than "no such method": a refusal that says nothing about
			// scoping.
			absentEverywhere = false
		}
	}
	if absentEverywhere {
		return nil, listAbsent
	}
	return nil, listRefused
}

// withV1Version adds the v1.0 revision header to a principal's own headers without
// mutating them.
func withV1Version(extra map[string]string) map[string]string {
	h := map[string]string{"A2A-Version": "1.0"}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

// createTask establishes a task owned by p, trying the v1.0 method name then the v0.3
// one. The observation is returned so a caller that got no task can say why rather
// than reporting a scoped listing it never tested.
func (e *TaskEnumerationExecutor) createTask(ctx context.Context, c *attack.HTTPClient, endpoint string,
	p attack.Principal, randID string) (taskID, contextID string, accepted bool, obs setupObservation) {
	resp, err := c.POST(ctx, endpoint, withV1Version(p.Headers), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "batesian-enum-create-" + p.Name + "-" + randID,
		"method":  "SendMessage",
		"params": map[string]interface{}{
			"message": map[string]interface{}{
				"role":      1, // ROLE_USER
				"parts":     []interface{}{map[string]string{"text": "batesian enumeration probe " + randID}},
				"messageId": "batesian-enum-" + p.Name + "-" + randID,
			},
		},
	})
	if err != nil || !resp.IsAccepted() {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			c.PresentsCredential(endpoint), resp))
		resp, err = c.POST(ctx, endpoint, p.Headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      "batesian-enum-create-" + p.Name + "-" + randID,
			"method":  "message/send",
			"params": map[string]interface{}{
				"message": map[string]interface{}{
					"role":      "user",
					"parts":     []interface{}{map[string]string{"kind": "text", "text": "batesian enumeration probe " + randID}},
					"messageId": "batesian-enum-" + p.Name + "-" + randID,
				},
			},
		})
	}
	if err != nil || !resp.IsAccepted() {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			c.PresentsCredential(endpoint), resp))
		return "", "", false, obs
	}
	taskID, contextID = extractTaskContext(resp.Body)
	if taskID == "" {
		obs.observe(classifyTaskSetup("creating a probe task as principal "+p.Name, endpoint,
			c.PresentsCredential(endpoint), resp))
	}
	return taskID, contextID, taskID != "", obs
}

func (e *TaskEnumerationExecutor) finding(endpoint string, a, b attack.Principal,
	taskID string, otherList []string) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "A2A ListTasks enumerates another principal's tasks (broken authorization scoping)",
		Description: fmt.Sprintf(
			"ListTasks at %s returned principal %s's task to principal %s, who has no claim to it. "+
				"The specification requires the opposite twice: section 3.1.4 states that "+
				"implementations MUST implement appropriate authorization scoping so clients can only "+
				"access authorized tasks, and section 13.1 that servers MUST return only tasks visible "+
				"to the authenticated client. Enumeration is worse than reading a task by id, because "+
				"it needs no prior knowledge: one valid credential yields every task identifier on the "+
				"server, and those identifiers are what the per-task read, cancel and push-config "+
				"surfaces take as input.", endpoint, a.Name, b.Name),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntask owner: %s (tenant %s)\nenumerating principal: %s (tenant %s)\n"+
				"task created by %s: %s\ntask ids returned to %s: %v\n"+
				"unauthenticated ListTasks: did not return the task, so authorization is enforced "+
				"and the failure is scoping between valid principals",
			endpoint, a.Name, a.Tenant, b.Name, b.Tenant, a.Name, taskID, b.Name, otherList),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}
