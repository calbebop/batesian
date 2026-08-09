package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/calbebop/batesian/internal/attack"
)

// TaskIDORExecutor tests whether MCP tasks are bound to the authorization
// context that created them (rule mcp-task-idor-001).
//
// MCP 2025-11-25 added durable tasks: a task-augmented tools/call returns a
// taskId, and the caller later reads state with tasks/get and the underlying
// tool output with tasks/result. The spec is explicit that these are scoped:
// "receivers MUST reject tasks/get, tasks/result, and tasks/cancel requests for
// tasks that do not belong to the same authorization context as the requestor."
//
// Two failures are reported. Reading another context's task metadata discloses
// status, timing and status messages. Reading its result discloses the actual
// tool output, which is the payload the task existed to produce.
//
// SAFETY: creating a task requires invoking a real tool, which no other rule in
// this package does (mcp-tools-unauth-001 deliberately calls a non-existent tool
// so nothing executes). To bound that, the rule only invokes a task-capable tool
// whose annotations declare it read-only or explicitly non-destructive, and
// skips entirely when no such tool exists.
//
// Tasks are marked experimental in 2025-11-25, so this rule is version-scoped.
//
// DO NOT PORT THIS CLAIM TO THE 2026-07-28 TASKS EXTENSION. In 2026-07-28 tasks
// left the core spec for extension io.modelcontextprotocol/tasks, whose normative
// text lives in the separate modelcontextprotocol/ext-tasks repository and releases
// independently. That extension deliberately DROPPED the requirement this rule
// tests. Its Security Considerations read, in full on this point:
//
//	"Task ID unguessability. A server MAY use task IDs as bearer tokens for a
//	server's stored state. Servers MUST generate them with sufficient entropy that
//	a third party cannot enumerate or guess them."
//
// So on the extension wire a server is EXPLICITLY PERMITTED to treat a
// high-entropy task ID as a capability, and answering tasks/get for anyone holding
// one is conformant. Reporting that as an IDOR would accuse a compliant server.
// The extension also removes tasks/result and tasks/list outright, so the two
// stronger findings here have no wire to sit on, and its own text notes that
// without tasks/list "a server cannot inadvertently leak the existence of one
// caller's tasks to another".
//
// What IS testable on the extension wire is the entropy MUST above, which is a
// different rule with a different oracle: predict the next task ID, committed
// before observation, and compare byte-for-byte.
//
// The 2025-11-25 requirement this rule does test is also conditional, which is why
// the anonymous-access discriminator below is not optional: "If context-binding is
// available, receivers MUST reject tasks/get, tasks/result, and tasks/cancel
// requests for tasks that do not belong to the same authorization context as the
// requestor." A server with no authorization context is held to the entropy
// requirement instead, not to this one.
type TaskIDORExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("mcp-task-idor", func(rc attack.RuleContext) attack.Executor { return NewTaskIDORExecutor(rc) })
}

func NewTaskIDORExecutor(r attack.RuleContext) *TaskIDORExecutor {
	return &TaskIDORExecutor{rule: r}
}

// taskPollBudget bounds how long the rule waits for a task to reach a terminal
// status. tasks/result blocks until terminal by spec, so the rule polls
// tasks/get instead and only calls tasks/result once the task has finished.
const (
	taskPollBudget   = 12 * time.Second
	taskPollInterval = 750 * time.Millisecond
	taskPollMaxTries = 16
)

// safeTool is a task-capable tool the rule is willing to invoke.
type safeTool struct {
	name string
	args map[string]interface{}
}

// authEvidence records what the discriminator established about the target's
// authentication, so a finding describes the boundary it actually measured rather
// than the one the rule originally assumed. enforcedOn names the surface a
// credential is required for; anonProbe is the single anonymous request that
// demonstrated it.
type authEvidence struct {
	enforcedOn string
	anonProbe  string
}

// taskPrincipal is one identity the rule acts as. Headers are carried alongside the
// token because a multi-tenant deployment commonly resolves the tenant at a gateway
// from a header, so two identities can differ by header and share a token. Ignoring
// them collapsed such a pair into one identity, which is how the same-credential
// false positive below could arise even from a correctly configured scan.
type taskPrincipal struct {
	name    string
	token   string
	headers map[string]string
}

// anonymous is the no-credential principal used by the discriminator.
var anonymousPrincipal = taskPrincipal{name: "anonymous"}

// taskPrincipals resolves the two identities this rule needs.
//
// It requires two DISTINCT credentials and reports not tested otherwise. The
// requirement under test is "receivers MUST bind tasks to said [authorization]
// context", so crossing it needs two contexts. The rule used to fall back to
// opts.Token for both identities and run anyway: two sessions of the same credential
// then satisfied the oracle, and a plain --token scan of a server that binds tasks to
// the authorization context exactly as the spec requires reported an IDOR at high and
// two more at critical. Session ids are not authorization contexts, so a server that
// declines to additionally bind to the session is not in violation.
//
// Two identities differing only by header are still two contexts, so distinctness is
// judged on the credential as sent, not on the token alone.
func taskPrincipals(opts attack.Options) (a, b taskPrincipal, err error) {
	if len(opts.Principals) < 2 {
		return a, b, fmt.Errorf("%w: this rule reads one authorization context's task as another "+
			"and %d principal(s) were configured; pass two --principal flags (or a config with two "+
			"principals) to run it", attack.ErrInconclusive, len(opts.Principals))
	}
	a = taskPrincipal{name: opts.Principals[0].Name, token: opts.Principals[0].Token,
		headers: opts.Principals[0].Headers}
	b = taskPrincipal{name: opts.Principals[1].Name, token: opts.Principals[1].Token,
		headers: opts.Principals[1].Headers}
	if a.token == b.token && sameHeaders(a.headers, b.headers) {
		return a, b, fmt.Errorf("%w: principals %q and %q present the same credential, so there is "+
			"no second authorization context for this rule to cross",
			attack.ErrInconclusive, a.name, b.name)
	}
	return a, b, nil
}

func sameHeaders(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// taskPremise is why one of this rule's preconditions did or did not hold.
//
// The distinction is the whole difference between "this server has no task surface"
// and "we could not find out". Both used to return clean, so a server whose tools/list
// was scope-gated, or whose task creation hit a 403 or a gateway error, was reported as
// having sound task scoping without a single task ever existing.
type taskPremise int

const (
	// premiseMet: the precondition holds and the rule can continue.
	premiseMet taskPremise = iota
	// premiseAbsent: the feature genuinely is not here. Not applicable, so clean.
	premiseAbsent
	// premiseUndetermined: the probe returned no protocol-level verdict. Not tested.
	premiseUndetermined
)

func (e *TaskIDORExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	vars := attack.NewVars(target, opts.OOBListenerURL)
	// One transport, with credentials attached per request, so each session can
	// present a different principal.
	client := attack.NewUnauthHTTPClient(opts, vars)

	// The credential check comes AFTER the capability gates below, deliberately. A
	// server with no task surface is not applicable whatever credentials were passed,
	// and telling an operator to add two principals when adding them would change
	// nothing is worse than saying the feature is absent. So discovery runs as the best
	// credential available, which is principal A whenever principals were configured.
	princA, princB, credErr := taskPrincipals(opts)
	discovery := princA
	if credErr != nil {
		discovery = taskPrincipal{name: "the configured credential", token: opts.Token}
	}

	// Session A, which also discovers the endpoint.
	sessA, initErr := e.initSession(ctx, client, vars.BaseURL, discovery)
	if initErr != nil {
		return nil, inconclusive(initErr) // not an MCP server, and why
	}

	// Gate on the tasks capability and on task-augmented tools/call specifically.
	if !sessA.ServerSupports("tasks") || !tasksSupportsToolCall(sessA.RawInit) {
		// A server carrying tasks under the 2026-07-28 extension advertises them
		// somewhere this rule does not look and speaks a wire it does not drive, so
		// the surface is present and untested rather than absent. Reporting clean
		// would assert that task scoping is sound on a server whose task surface was
		// never touched.
		if tasksExtensionAdvertised(sessA.RawInit) || sessA.ProtocolVersion >= modernEraVersion {
			return nil, fmt.Errorf("%w: %s carries tasks under the %s extension rather than the "+
				"2025-11-25 core capability, and this rule drives the core wire only",
				attack.ErrInconclusive, sessA.Endpoint, tasksExtensionName)
		}
		return nil, nil
	}

	// The task surface is present, so a missing second identity is now the reason the
	// rule cannot run rather than a detail about a server it does not apply to.
	if credErr != nil {
		return nil, credErr
	}

	// Gate on finding a tool this rule is willing to invoke.
	tool, toolPremise := e.findSafeTaskTool(ctx, client, sessA, princA, vars.RandID)
	switch toolPremise {
	case premiseAbsent:
		return nil, nil // no tool declares itself safe to invoke: nothing to test, honestly
	case premiseUndetermined:
		return nil, fmt.Errorf("%w: tools/list at %s returned no usable answer for principal %s, so "+
			"no task could be created and task scoping was never exercised",
			attack.ErrInconclusive, sessA.Endpoint, princA.name)
	}

	// Step 1: create a task as principal A.
	taskID, createPremise := e.createTask(ctx, client, sessA, princA, tool)
	if createPremise != premiseMet {
		// Either way the rule's premise (a task exists to be read across a boundary)
		// was never established, so there is nothing to call secure. This includes a
		// server that advertised task-augmented tools/call and then answered without a
		// taskId, which is a deviation rather than an absent feature.
		return nil, fmt.Errorf("%w: principal %s could not create a task with %s at %s, so there was "+
			"no task for another authorization context to read",
			attack.ErrInconclusive, princA.name, tool.name, sessA.Endpoint)
	}

	// Step 2: discriminator. This rule claims task reads are not bound to the
	// creating authorization context, which presupposes there is an authorization
	// context at all. A server that authenticates nothing is a different and more
	// obvious failure, owned by mcp-tools-unauth-001, and must not be called an IDOR.
	//
	// "Authenticates nothing" has to be measured on the read surface too, not on
	// creation alone. A server can leave a task-augmented tools/call open while
	// gating tasks/get and tasks/result, and that gate is a real authorization
	// boundary: an anonymous caller is refused, an authenticated one is not, and
	// which tasks the authenticated one may read is exactly this rule's question.
	// Suppressing on open creation alone hid that server completely.
	// Each branch below records only what it actually observed, so no finding
	// claims a probe that was skipped. The read probe runs only when creation was
	// open, because a refused creation already proves a credential is required.
	// Every branch records only what it observed. A control that produced no verdict
	// stops the rule instead of being written down as a refusal: the evidence line
	// "anonymous task creation: refused" used to be emitted whenever the anonymous
	// create returned nothing, including when it failed in transport or hit a 429, so a
	// finding asserted an authorization boundary the rule had not seen.
	auth := authEvidence{
		enforcedOn: "the MCP endpoint",
		anonProbe:  "anonymous initialize: refused",
	}
	if anonSess, anonErr := e.initSession(ctx, client, vars.BaseURL, anonymousPrincipal); anonErr == nil {
		anonTask, anonPremise := e.createTask(ctx, client, anonSess, anonymousPrincipal, tool)
		switch anonPremise {
		case premiseUndetermined:
			return nil, fmt.Errorf("%w: the anonymous control at %s returned no verdict, so whether "+
				"this server has an authorization context could not be established; the requirement "+
				"under test binds only on servers that do",
				attack.ErrInconclusive, sessA.Endpoint)
		case premiseMet:
			_ = anonTask
			switch _, anonRead := e.getTask(ctx, client, anonSess, anonymousPrincipal, taskID); anonRead {
			case probeAnswered:
				return nil, nil // no credential is required anywhere: mcp-tools-unauth-001's surface
			case probeInconclusive:
				return nil, fmt.Errorf("%w: an anonymous caller could create a task at %s but the "+
					"anonymous read of principal %s's task returned no verdict, so whether reads are "+
					"gated at all could not be established",
					attack.ErrInconclusive, sessA.Endpoint, princA.name)
			}
			auth = authEvidence{
				enforcedOn: "task reads only (anonymous task creation was accepted)",
				anonProbe:  "anonymous tasks/get: refused",
			}
		default:
			auth = authEvidence{
				enforcedOn: "task creation and reads",
				anonProbe:  "anonymous task creation: refused",
			}
		}
	}

	// Step 3: a second session, as principal B, tries to read A's task.
	//
	// No session-id comparison. Session ids are not authorization contexts, and
	// requiring them to differ made the rule a silent no-op against every stateless
	// deployment: those mint no Mcp-Session-Id, both ids were empty, and the rule
	// returned clean without sending step 4 at all.
	sessB, errB := e.initSession(ctx, client, vars.BaseURL, princB)
	if errB != nil {
		return nil, fmt.Errorf("%w: principal %s could not open a session at %s (%v), so its access "+
			"to principal %s's task was never tested",
			attack.ErrInconclusive, princB.name, vars.BaseURL, errB, princA.name)
	}

	var findings []attack.Finding

	// Step 4: can B read A's task by id? A correctly-scoped server answers -32602.
	meta, readVerdict := e.getTask(ctx, client, sessB, princB, taskID)
	switch readVerdict {
	case probeInconclusive:
		return nil, fmt.Errorf("%w: principal %s's read of principal %s's task %s at %s returned no "+
			"verdict, so whether the task is bound to its creating context was never observed",
			attack.ErrInconclusive, princB.name, princA.name, taskID, sessA.Endpoint)
	case probeAnswered:
		findings = append(findings, e.metadataFinding(sessA.Endpoint, taskID, meta, true, auth))

		// Escalate if B can also read the result. tasks/result blocks until the
		// task is terminal, so poll tasks/get first and stay inside the budget.
		if e.pollTerminal(ctx, client, sessB, princB, taskID) {
			if content, ok := e.getResult(ctx, client, sessB, princB, taskID); ok {
				findings = append(findings, e.resultFinding(sessA.Endpoint, taskID, tool.name, content, true, auth))
			}
		}
	}

	// Step 5: can B enumerate A's task without knowing its id? This is checked
	// independently of step 4: the spec requires anything gettable to also be
	// listable, but not the converse, so a server can scope tasks/get and still
	// leak the list. Enumeration is the stronger failure because it needs no
	// prior knowledge of the task id at all.
	if tasksSupportsList(sessA.RawInit) {
		if ids, ok := e.listTasks(ctx, client, sessB, princB); ok && containsTaskID(ids, taskID) {
			findings = append(findings, e.enumerationFinding(sessA.Endpoint, taskID, len(ids), true, auth))
		}
	}

	return findings, nil
}

// initSession performs an initialize handshake as the given token, discovering
// the endpoint across the candidate paths, and returns the resulting session.
func (e *TaskIDORExecutor) initSession(ctx context.Context, client *attack.HTTPClient, baseURL string, p taskPrincipal) (mcpSession, error) {
	// Why the walk failed, classified from the responses this loop already has, so a
	// rule that could not run says what happened instead of blaming the network.
	var observed initObservation
	for _, ep := range endpointCandidates(baseURL) {
		headers := map[string]string{}
		if p.token != "" {
			headers["Authorization"] = "Bearer " + p.token
		}
		for k, v := range p.headers {
			headers[k] = v
		}
		resp, err := client.POST(ctx, ep, headers, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]interface{}{
				"protocolVersion": "2025-11-25",
				// Declaring the tasks client capability keeps the handshake
				// honest: this client really does poll and cancel tasks.
				"capabilities": map[string]interface{}{
					"tasks": map[string]interface{}{"list": map[string]interface{}{}, "cancel": map[string]interface{}{}},
				},
				"clientInfo": map[string]interface{}{"name": "batesian", "version": "1.0"},
			},
		})
		if err != nil {
			continue // transport failure: nothing answered, so nothing to explain
		}
		if !resp.IsSuccess() || !resp.ContainsAny(`"protocolVersion"`, `"serverInfo"`, `"capabilities"`) {
			// This rule presents a token explicitly, so the client's ambient
			// credential is not what decides whether the request carried one.
			observed.observe(classifyInitFailure(ep, p.token != "", resp))
			continue
		}
		session := mcpSession{
			Endpoint:        ep,
			SessionID:       resp.Headers.Get("Mcp-Session-Id"),
			ProtocolVersion: negotiatedVersion(resp.Body),
			RawInit:         resp.Body,
		}
		_, _ = client.POST(ctx, ep, e.headers(session, p), map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/initialized",
		})
		return session, nil
	}
	if observed.rank > rankNothing {
		return mcpSession{}, handshakeRefusal{observed.reason}
	}
	return mcpSession{}, fmt.Errorf("no MCP server found at %s", baseURL)
}

// headers builds the per-request headers for a session and principal.
func (e *TaskIDORExecutor) headers(s mcpSession, p taskPrincipal) map[string]string {
	h := map[string]string{}
	if s.ProtocolVersion != "" {
		h["Mcp-Protocol-Version"] = s.ProtocolVersion
	}
	if s.SessionID != "" {
		h["Mcp-Session-Id"] = s.SessionID
	}
	if p.token != "" {
		h["Authorization"] = "Bearer " + p.token
	}
	// A principal's own headers last: a tenant resolved at a gateway is part of the
	// credential this identity presents, and omitting it made two identities one.
	for k, v := range p.headers {
		h[k] = v
	}
	return h
}

// tasksSupportsToolCall reports whether the handshake declared
// capabilities.tasks.requests.tools.call, which is what permits augmenting a
// tools/call with a task.
func tasksSupportsToolCall(rawInit []byte) bool {
	var body struct {
		Result struct {
			Capabilities struct {
				Tasks struct {
					Requests struct {
						Tools map[string]json.RawMessage `json:"tools"`
					} `json:"requests"`
				} `json:"tasks"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rawInit, &body); err != nil {
		return false
	}
	_, ok := body.Result.Capabilities.Tasks.Requests.Tools["call"]
	return ok
}

// tasksSupportsList reports whether the handshake declared capabilities.tasks.list,
// which is what permits tasks/list at all. The spec tells receivers that cannot
// identify requestors not to declare it, precisely because listing exposes task
// metadata regardless of how much entropy the task ids carry.
func tasksSupportsList(rawInit []byte) bool {
	var body struct {
		Result struct {
			Capabilities struct {
				Tasks map[string]json.RawMessage `json:"tasks"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rawInit, &body); err != nil {
		return false
	}
	_, ok := body.Result.Capabilities.Tasks["list"]
	return ok
}

// listTasks enumerates the tasks visible to the given principal, returning the
// task ids from the first page. ok is false when the server refuses the call.
func (e *TaskIDORExecutor) listTasks(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal) ([]string, bool) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, p), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      6,
		"method":  "tasks/list",
		"params":  map[string]interface{}{},
	})
	if err != nil || !resp.IsSuccess() {
		return nil, false
	}
	var body struct {
		Result *struct {
			Tasks []struct {
				TaskID string `json:"taskId"`
			} `json:"tasks"`
		} `json:"result"`
		Error map[string]interface{} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, false
	}
	if body.Error != nil || body.Result == nil {
		return nil, false
	}
	ids := make([]string, 0, len(body.Result.Tasks))
	for _, t := range body.Result.Tasks {
		if t.TaskID != "" {
			ids = append(ids, t.TaskID)
		}
	}
	return ids, true
}

// containsTaskID reports whether the enumerated list includes the target task.
func containsTaskID(ids []string, taskID string) bool {
	for _, id := range ids {
		if id == taskID {
			return true
		}
	}
	return false
}

// findSafeTaskTool picks a task-capable tool the rule is willing to invoke, and
// synthesizes arguments for it from its input schema.
//
// Task creation is the one place this package executes real server-side
// functionality, so the tool must declare itself read-only or explicitly
// non-destructive. A tool with no annotations is not invoked: MCP treats
// destructiveHint as true by default when a tool is not read-only.
func (e *TaskIDORExecutor) findSafeTaskTool(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal, randID string) (safeTool, taskPremise) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, p), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	})
	// A listing this principal cannot read is not an absent task surface. It used to
	// collapse into the same "no safe tool" verdict as an answered-but-empty listing,
	// so a scope-gated tools/call reported task scoping sound with no task ever made.
	if verdict, _ := classifyProbe(resp, err); verdict != probeAnswered {
		return safeTool{}, premiseUndetermined
	}
	var body struct {
		Result struct {
			Tools []struct {
				Name      string `json:"name"`
				Execution struct {
					TaskSupport string `json:"taskSupport"`
				} `json:"execution"`
				Annotations *struct {
					ReadOnlyHint    *bool `json:"readOnlyHint"`
					DestructiveHint *bool `json:"destructiveHint"`
				} `json:"annotations"`
				InputSchema map[string]interface{} `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return safeTool{}, premiseUndetermined
	}
	for _, t := range body.Result.Tools {
		if t.Execution.TaskSupport != "optional" && t.Execution.TaskSupport != "required" {
			continue
		}
		if t.Annotations == nil {
			continue // unannotated: assume it may be destructive
		}
		readOnly := t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
		nonDestructive := t.Annotations.DestructiveHint != nil && !*t.Annotations.DestructiveHint
		if !readOnly && !nonDestructive {
			continue
		}
		return safeTool{name: t.Name, args: synthesizeArgs(t.InputSchema, randID)}, premiseMet
	}
	// The listing was read and no tool declares itself safe to invoke. Genuinely not
	// applicable, so clean.
	return safeTool{}, premiseAbsent
}

// synthesizeArgs builds a minimal argument object from a tool's JSON Schema,
// filling each declared property with an inert value of the right type.
func synthesizeArgs(schema map[string]interface{}, randID string) map[string]interface{} {
	args := map[string]interface{}{}
	props, _ := schema["properties"].(map[string]interface{})
	for name, raw := range props {
		spec, _ := raw.(map[string]interface{})
		switch spec["type"] {
		case "string":
			args[name] = "batesian task probe " + randID
		case "number", "integer":
			args[name] = 1
		case "boolean":
			args[name] = false
		case "array":
			args[name] = []interface{}{}
		case "object":
			args[name] = map[string]interface{}{}
		}
	}
	return args
}

// createTask issues a task-augmented tools/call and returns the created task id.
//
// The premise distinguishes a refusal, which the anonymous control reads as "a
// credential is required here", from a probe that produced no verdict at all. Both
// used to return an empty id, so a transport failure or a 429 on the anonymous control
// was written into a finding's evidence as "anonymous task creation: refused".
func (e *TaskIDORExecutor) createTask(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal, tool safeTool) (string, taskPremise) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, p), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      tool.name,
			"arguments": tool.args,
			"task":      map[string]interface{}{"ttl": 60000},
		},
	})
	verdict, _ := classifyProbe(resp, err)
	switch verdict {
	case probeInconclusive:
		return "", premiseUndetermined
	case probeRejected:
		return "", premiseAbsent
	}
	var body struct {
		Result struct {
			Task struct {
				TaskID string `json:"taskId"`
			} `json:"task"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return "", premiseUndetermined
	}
	if body.Result.Task.TaskID == "" {
		// Answered, but with no task handle, on a server that advertised
		// capabilities.tasks.requests.tools.call. That is a deviation rather than an
		// absent feature, and either way no task exists to read across a boundary.
		return "", premiseUndetermined
	}
	return body.Result.Task.TaskID, premiseMet
}

// taskState is the subset of a Task object the rule reports on.
type taskState struct {
	Status        string `json:"status"`
	StatusMessage string `json:"statusMessage"`
	CreatedAt     string `json:"createdAt"`
}

// getTask reads a task as the given principal.
//
// probeAnswered means the task came back, probeRejected means the server refused (the
// correctly-scoped outcome, a -32602 per spec), and probeInconclusive means the request
// produced no verdict. The third used to be indistinguishable from a refusal, in both
// directions: on the anonymous control it read as "reads are gated", and on the
// cross-principal read it read as "the task is bound to its creating context".
func (e *TaskIDORExecutor) getTask(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal, taskID string) (taskState, probeVerdict) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, p), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tasks/get",
		"params":  map[string]interface{}{"taskId": taskID},
	})
	verdict, _ := classifyProbe(resp, err)
	if verdict != probeAnswered {
		return taskState{}, verdict
	}
	var body struct {
		Result *taskState             `json:"result"`
		Error  map[string]interface{} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return taskState{}, probeInconclusive
	}
	// A JSON-RPC error at HTTP 200 is the spec'd refusal shape, so it is a real answer.
	if body.Error != nil {
		return taskState{}, probeRejected
	}
	if body.Result == nil || body.Result.Status == "" {
		// 2xx, no error, and no task: nothing was refused and nothing was disclosed.
		return taskState{}, probeInconclusive
	}
	return *body.Result, probeAnswered
}

// pollTerminal waits for the task to reach a terminal status, within budget.
// tasks/result blocks until terminal, so polling first keeps the scan bounded.
func (e *TaskIDORExecutor) pollTerminal(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal, taskID string) bool {
	deadline := time.Now().Add(taskPollBudget)
	for i := 0; i < taskPollMaxTries && time.Now().Before(deadline); i++ {
		st, verdict := e.getTask(ctx, client, s, p, taskID)
		if verdict != probeAnswered {
			return false
		}
		switch st.Status {
		case "completed", "failed", "cancelled":
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(taskPollInterval):
		}
	}
	return false
}

// getResult reads the underlying tool output for a terminal task, returning the
// raw result payload when the server disclosed it.
func (e *TaskIDORExecutor) getResult(ctx context.Context, client *attack.HTTPClient, s mcpSession, p taskPrincipal, taskID string) (string, bool) {
	resp, err := client.POST(ctx, s.Endpoint, e.headers(s, p), map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tasks/result",
		"params":  map[string]interface{}{"taskId": taskID},
	})
	if err != nil || !resp.IsSuccess() {
		return "", false
	}
	var body struct {
		Result json.RawMessage        `json:"result"`
		Error  map[string]interface{} `json:"error"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return "", false
	}
	if body.Error != nil || len(body.Result) == 0 {
		return "", false
	}
	return string(body.Result), true
}

// requestorLabel describes what boundary was actually crossed, so the finding
// never claims a cross-principal read when only two sessions were available.
func requestorLabel(crossPrincipal bool) string {
	if crossPrincipal {
		return "a different authenticated principal"
	}
	return "a separate authenticated session"
}

func (e *TaskIDORExecutor) metadataFinding(endpoint, taskID string, st taskState, crossPrincipal bool, auth authEvidence) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "high",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP task readable by another authorization context (tasks/get IDOR)",
		Description: fmt.Sprintf(
			"tasks/get at %s returned task %s to %s that did not create it. Authentication is enforced "+
				"on %s, so a credential is required, yet task lookup is not bound to the creating "+
				"context. The MCP spec requires receivers to reject tasks/get for tasks outside the "+
				"requestor's authorization context, so any caller who learns or guesses a task id can "+
				"track another context's work.",
			endpoint, taskID, requestorLabel(crossPrincipal), auth.enforcedOn),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntask: %s\nauthentication enforced on: %s\n%s\n"+
				"cross-context tasks/get: accepted\n"+
				"disclosed status: %s\nstatusMessage: %s\ncreatedAt: %s",
			endpoint, taskID, auth.enforcedOn, auth.anonProbe, st.Status, st.StatusMessage, st.CreatedAt),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func (e *TaskIDORExecutor) enumerationFinding(endpoint, taskID string, total int, crossPrincipal bool, auth authEvidence) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "critical",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP tasks/list enumerates another authorization context's tasks",
		Description: fmt.Sprintf(
			"tasks/list at %s returned task %s to %s that did not create it, in a list of %d task(s). "+
				"This is a stronger failure than reading a task by id: the caller needs no prior knowledge "+
				"of any task id, so every task on the server can be enumerated and then read. The MCP spec "+
				"requires receivers to return only tasks associated with the requestor's authorization "+
				"context, and to not advertise the tasks.list capability at all when requestors cannot be "+
				"identified.", endpoint, taskID, requestorLabel(crossPrincipal), total),
		Evidence: fmt.Sprintf(
			"endpoint: %s\nauthentication enforced on: %s\n%s\n"+
				"cross-context tasks/list: accepted\ntasks returned: %d\nincludes another context's task: %s",
			endpoint, auth.enforcedOn, auth.anonProbe, total, taskID),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

func (e *TaskIDORExecutor) resultFinding(endpoint, taskID, toolName, content string, crossPrincipal bool, auth authEvidence) attack.Finding {
	return attack.Finding{
		RuleID:     e.rule.ID,
		RuleName:   e.rule.Name,
		Severity:   "critical",
		Confidence: attack.ConfirmedExploit,
		Title:      "MCP task result readable by another authorization context (tasks/result IDOR)",
		Description: fmt.Sprintf(
			"tasks/result at %s returned the completed output of task %s to %s that did not create it. "+
				"This is the actual result of the %q tool invocation, not task metadata, so whatever that "+
				"tool returned is disclosed across the authorization boundary. The MCP spec requires "+
				"receivers to reject tasks/result for tasks outside the requestor's authorization context.",
			endpoint, taskID, requestorLabel(crossPrincipal), toolName),
		Evidence: fmt.Sprintf(
			"endpoint: %s\ntask: %s\ntool: %s\nauthentication enforced on: %s\n%s\n"+
				"cross-context tasks/result: accepted\ndisclosed result: %s",
			endpoint, taskID, toolName, auth.enforcedOn, auth.anonProbe, snippetMCP([]byte(content))),
		Remediation: e.rule.Remediation,
		TargetURL:   endpoint,
	}
}

// tasksExtensionName is the identifier the 2026-07-28 tasks extension is
// advertised under.
const tasksExtensionName = "io.modelcontextprotocol/tasks"

// tasksExtensionAdvertised reports whether the handshake declared the 2026-07-28
// tasks extension, at capabilities.extensions["io.modelcontextprotocol/tasks"].
//
// A server advertising this is not one this rule can assess: the extension removed
// tasks/result and tasks/list and dropped the context-binding requirement, so the
// rule's oracle does not apply to it. Distinguishing it from a server with no tasks
// at all is what keeps the report honest.
func tasksExtensionAdvertised(rawInit []byte) bool {
	var body struct {
		Result struct {
			Capabilities struct {
				Extensions map[string]json.RawMessage `json:"extensions"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if json.Unmarshal(rawInit, &body) != nil {
		return false
	}
	_, ok := body.Result.Capabilities.Extensions[tasksExtensionName]
	return ok
}
