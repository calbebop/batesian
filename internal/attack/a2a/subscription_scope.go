package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

// SubscriptionScopeExecutor compares task reads and subscriptions across principals.
type SubscriptionScopeExecutor struct {
	rule attack.RuleContext
}

func init() {
	attack.Register("a2a-subscription-scope", func(rc attack.RuleContext) attack.Executor {
		return NewSubscriptionScopeExecutor(rc)
	})
}

func NewSubscriptionScopeExecutor(r attack.RuleContext) *SubscriptionScopeExecutor {
	return &SubscriptionScopeExecutor{rule: r}
}

func (e *SubscriptionScopeExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	ctx = withTenantRouting(ctx)
	owner, other, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	clientA, clientB := principalClient(opts, vars, owner), principalClient(opts, vars, other)
	endpoint, jsonRPC := resolveA2AEndpoint(ctx, attack.NewUnauthHTTPClient(opts, vars), vars.BaseURL)
	var partial error
	if jsonRPC {
		findings, err := e.probeJSONRPC(ctx, endpoint, vars.RandID, owner, other, clientA, clientB)
		if len(findings) != 0 {
			return findings, err
		}
		partial = errors.Join(partial, err)
	}
	findings, restErr, restAdvertised := e.probeREST(ctx, vars.BaseURL, vars.RandID, owner, other, clientA, clientB)
	if len(findings) != 0 {
		return findings, errors.Join(partial, restErr)
	}
	if !jsonRPC && !restAdvertised {
		return nil, attack.ErrInconclusive
	}
	return nil, errors.Join(partial, restErr)
}

func (e *SubscriptionScopeExecutor) probeJSONRPC(ctx context.Context, endpoint, randID string,
	owner, other attack.Principal, clientA, clientB *attack.HTTPClient) ([]attack.Finding, error) {
	taskID, setup := NewPushBindingExecutor(e.rule).createTask(ctx, clientA, endpoint, owner, randID)
	if taskID == "" {
		return nil, setup.err()
	}
	partial := setup.partialErr()

	for _, wire := range []struct {
		v1        bool
		get       string
		subscribe string
	}{
		{true, "GetTask", "SubscribeToTask"},
		{false, "tasks/get", "tasks/resubscribe"},
	} {
		ownerRead := e.readTask(ctx, clientA, endpoint, owner.Headers, taskID, wire.get, wire.v1, randID+"-owner")
		if ownerRead.kind == subscriptionUnsupported {
			continue
		}
		if ownerRead.kind != subscriptionData || !activeTaskState(ownerRead.state) {
			partial = errors.Join(partial, fmt.Errorf("%w: owner task read did not confirm a nonterminal task on %s", attack.ErrInconclusive, wire.get))
			continue
		}
		ownerStream := e.subscribe(ctx, clientA, endpoint, owner.Headers, taskID, wire.subscribe, wire.v1, randID+"-owner")
		if ownerStream.kind == subscriptionUnsupported {
			continue
		}
		if ownerStream.kind != subscriptionData || (wire.v1 && !activeTaskState(ownerStream.state)) ||
			ownerStream.contextID != ownerRead.contextID {
			partial = errors.Join(partial, fmt.Errorf("%w: owner subscription did not return matching task data on %s", attack.ErrInconclusive, wire.subscribe))
			continue
		}
		otherRead := e.readTask(ctx, clientB, endpoint, other.Headers, taskID, wire.get, wire.v1, randID+"-other")
		if otherRead.kind != subscriptionDenied {
			partial = errors.Join(partial, fmt.Errorf("%w: second principal was not confirmed outside the task's access scope on %s", attack.ErrInconclusive, wire.get))
			continue
		}
		otherStream := e.subscribe(ctx, clientB, endpoint, other.Headers, taskID, wire.subscribe, wire.v1, randID+"-other")
		switch otherStream.kind {
		case subscriptionData:
			if otherStream.contextID != ownerStream.contextID {
				partial = errors.Join(partial, fmt.Errorf("%w: second principal's %s event did not match the owner's context", attack.ErrInconclusive, wire.subscribe))
				continue
			}
			return []attack.Finding{e.finding(endpoint, owner, other, wire.get, wire.subscribe)}, partial
		case subscriptionDenied:
			// The owner can subscribe, while this principal cannot read or subscribe.
		default:
			partial = errors.Join(partial, fmt.Errorf("%w: second principal's %s response was unjudged", attack.ErrInconclusive, wire.subscribe))
		}
	}
	return nil, partial
}

type subscriptionOutcome uint8

const (
	subscriptionUnknown subscriptionOutcome = iota
	subscriptionUnsupported
	subscriptionDenied
	subscriptionData
)

type subscriptionProbe struct {
	kind      subscriptionOutcome
	state     string
	contextID string
}

func (e *SubscriptionScopeExecutor) readTask(ctx context.Context, c *attack.HTTPClient, endpoint string,
	headers map[string]string, taskID, method string, v1 bool, suffix string) subscriptionProbe {
	return e.taskRequest(ctx, c, endpoint, headers, taskID, method, v1, suffix, false)
}

func (e *SubscriptionScopeExecutor) subscribe(ctx context.Context, c *attack.HTTPClient, endpoint string,
	headers map[string]string, taskID, method string, v1 bool, suffix string) subscriptionProbe {
	return e.taskRequest(ctx, c, endpoint, headers, taskID, method, v1, suffix, true)
}

func (e *SubscriptionScopeExecutor) taskRequest(ctx context.Context, c *attack.HTTPClient, endpoint string,
	headers map[string]string, taskID, method string, v1 bool, suffix string, stream bool) subscriptionProbe {
	requestID := "batesian-subscription-" + suffix + "-" + method
	resp, err := c.POST(ctx, endpoint, pushBindingHeaders(headers, v1), map[string]interface{}{
		"jsonrpc": "2.0", "id": requestID, "method": method,
		"params": map[string]interface{}{"id": taskID},
	})
	if err != nil || resp == nil {
		return subscriptionProbe{}
	}
	if resp.StatusCode == http.StatusMethodNotAllowed {
		return subscriptionProbe{kind: subscriptionUnsupported}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return subscriptionProbe{kind: subscriptionDenied}
	}
	if !resp.IsSuccess() {
		return subscriptionProbe{}
	}
	result, code, hasError, valid := discoveryResponse(resp.Body, requestID)
	if !valid {
		return subscriptionProbe{}
	}
	if hasError {
		if code == jsonRPCMethodNotFound || code == a2aUnsupportedOperation {
			return subscriptionProbe{kind: subscriptionUnsupported}
		}
		message := strings.ToLower(jsonRPCErrorMessage(resp.Body))
		if code == -32001 || attack.AuthFlavoredMessage(message) || strings.Contains(message, "not found") ||
			strings.Contains(message, "not task owner") {
			return subscriptionProbe{kind: subscriptionDenied}
		}
		return subscriptionProbe{}
	}
	if stream && !strings.Contains(strings.ToLower(resp.Headers.Get("Content-Type")), "text/event-stream") {
		return subscriptionProbe{}
	}
	state, matched := taskStateForID(resp.Body, taskID)
	if matched && state != "" {
		if contextID := subscriptionContextID(result); contextID != "" {
			return subscriptionProbe{kind: subscriptionData, state: state, contextID: contextID}
		}
	}
	if stream && !v1 {
		var event struct {
			TaskID    string `json:"taskId"`
			ContextID string `json:"contextId"`
			Kind      string `json:"kind"`
			Status    struct {
				State string `json:"state"`
			} `json:"status"`
			Artifact json.RawMessage `json:"artifact"`
		}
		if json.Unmarshal(result, &event) == nil && event.TaskID == taskID && event.ContextID != "" &&
			(event.Kind == "status-update" && event.Status.State != "" ||
				event.Kind == "artifact-update" && len(event.Artifact) > 0 && string(event.Artifact) != "null") {
			return subscriptionProbe{kind: subscriptionData, state: event.Status.State, contextID: event.ContextID}
		}
	}
	return subscriptionProbe{}
}

func subscriptionContextID(result json.RawMessage) string {
	var value struct {
		ContextID string `json:"contextId"`
		Task      *struct {
			ContextID string `json:"contextId"`
		} `json:"task"`
	}
	if json.Unmarshal(result, &value) != nil {
		return ""
	}
	if value.Task != nil {
		return value.Task.ContextID
	}
	return value.ContextID
}

func (e *SubscriptionScopeExecutor) finding(endpoint string, owner, other attack.Principal, readMethod, method string) attack.Finding {
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.RiskIndicator,
		Title: "A2A subscription returned task data despite read denial",
		Description: fmt.Sprintf("Principal %q could not read principal %q's task, but received its task data from %s. Confirm whether the subscription grant is intended.",
			other.Name, owner.Name, method),
		Evidence: fmt.Sprintf("owner: %s\nother principal: %s\n%s: owner event received; other principal's %s denied; other principal's subscription returned data for the same task and context",
			owner.Name, other.Name, method, readMethod),
		Remediation: e.rule.Remediation, TargetURL: endpoint,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "create and subscribe to a nonterminal task", Outcome: "owner task event received"},
			{Hop: 2, Principal: other.Name, Action: "read owner task", Outcome: "denied"},
			{Hop: 3, Principal: other.Name, Action: "subscribe to owner task", Outcome: "task data received"},
		},
	}
}
