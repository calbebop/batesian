package a2a

import (
	"context"
	"fmt"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2apb/v1"
	"github.com/calbebop/batesian/internal/attack"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const maxGRPCTaskListPages = 3

type grpcScopeResult struct {
	found, matched, denied, unsupported bool
	err                                 error
}

func grpcListTask(ctx context.Context, client a2apb.A2AServiceClient, timeout time.Duration,
	headers map[string]string, taskID, marker string) grpcScopeResult {
	pageToken := ""
	seen := map[string]bool{}
	for page := 0; page < maxGRPCTaskListPages; page++ {
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		callCtx, err := grpcCallContext(callCtx, headers)
		if err != nil {
			cancel()
			return grpcScopeResult{err: fmt.Errorf("%w: invalid gRPC list metadata", attack.ErrInconclusive)}
		}
		pageSize, historyLength, includeArtifacts := int32(100), int32(10), true
		response, err := client.ListTasks(callCtx, &a2apb.ListTasksRequest{
			PageSize: &pageSize, PageToken: pageToken, HistoryLength: &historyLength, IncludeArtifacts: &includeArtifacts,
		})
		cancel()
		if err != nil {
			if page == 0 {
				switch status.Code(err) {
				case codes.Unimplemented:
					return grpcScopeResult{unsupported: true}
				case codes.Unauthenticated, codes.PermissionDenied:
					return grpcScopeResult{denied: true}
				}
			}
			return grpcScopeResult{err: fmt.Errorf("%w: gRPC ListTasks could not complete (status %s)",
				attack.ErrInconclusive, status.Code(err))}
		}
		if response == nil || len(response.GetTasks()) > int(pageSize) {
			return grpcScopeResult{err: fmt.Errorf("%w: gRPC ListTasks returned an invalid page", attack.ErrInconclusive)}
		}
		for _, task := range response.GetTasks() {
			if task == nil || task.GetId() != taskID {
				continue
			}
			body, err := protojson.Marshal(task)
			if err != nil {
				return grpcScopeResult{err: fmt.Errorf("%w: gRPC ListTasks task could not be decoded", attack.ErrInconclusive)}
			}
			location, _ := taskMarkerLocation(body, taskID, marker)
			return grpcScopeResult{found: true, matched: location != ""}
		}
		next := response.GetNextPageToken()
		if next == "" {
			return grpcScopeResult{}
		}
		if seen[next] {
			return grpcScopeResult{err: fmt.Errorf("%w: gRPC ListTasks repeated a page token", attack.ErrInconclusive)}
		}
		seen[next] = true
		pageToken = next
	}
	return grpcScopeResult{err: fmt.Errorf("%w: gRPC ListTasks exceeded the page cap", attack.ErrInconclusive)}
}

func grpcSubscribeTask(ctx context.Context, client a2apb.A2AServiceClient, timeout time.Duration,
	headers map[string]string, taskID, marker string) grpcScopeResult {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	callCtx, err := grpcCallContext(callCtx, headers)
	if err != nil {
		return grpcScopeResult{err: fmt.Errorf("%w: invalid gRPC subscription metadata", attack.ErrInconclusive)}
	}
	stream, err := client.SubscribeToTask(callCtx, &a2apb.SubscribeToTaskRequest{Id: taskID})
	if err == nil {
		var response *a2apb.StreamResponse
		response, err = stream.Recv()
		if err == nil && response != nil {
			task := response.GetTask()
			if task == nil || task.GetId() != taskID {
				return grpcScopeResult{err: fmt.Errorf("%w: gRPC SubscribeToTask did not begin with the requested task",
					attack.ErrInconclusive)}
			}
			switch task.GetStatus().GetState() {
			case a2apb.TaskState_TASK_STATE_SUBMITTED, a2apb.TaskState_TASK_STATE_WORKING,
				a2apb.TaskState_TASK_STATE_INPUT_REQUIRED, a2apb.TaskState_TASK_STATE_AUTH_REQUIRED:
			default:
				return grpcScopeResult{err: fmt.Errorf("%w: gRPC subscription task was not active",
					attack.ErrInconclusive)}
			}
			body, marshalErr := protojson.Marshal(task)
			if marshalErr != nil {
				return grpcScopeResult{err: fmt.Errorf("%w: gRPC subscription task could not be decoded", attack.ErrInconclusive)}
			}
			location, _ := taskMarkerLocation(body, taskID, marker)
			return grpcScopeResult{found: true, matched: location != ""}
		}
	}
	switch status.Code(err) {
	case codes.Unimplemented:
		return grpcScopeResult{unsupported: true}
	case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound:
		return grpcScopeResult{denied: true}
	default:
		return grpcScopeResult{err: fmt.Errorf("%w: gRPC SubscribeToTask returned no usable initial event (status %s)",
			attack.ErrInconclusive, status.Code(err))}
	}
}

func (e *GRPCTaskAccessExecutor) checkGRPCListScope(ctx context.Context, client a2apb.A2AServiceClient,
	timeout time.Duration, target string, owner, reader attack.Principal,
	ownerHeaders, readerHeaders map[string]string, taskID, marker string,
	denials []attack.ExpectedDenial) ([]attack.Finding, error) {
	owned := grpcListTask(ctx, client, timeout, ownerHeaders, taskID, marker)
	if owned.unsupported {
		return nil, nil
	}
	if owned.err != nil || !owned.matched {
		return nil, fmt.Errorf("%w: owner gRPC ListTasks did not show the marked task", attack.ErrInconclusive)
	}
	anonymous := grpcListTask(ctx, client, timeout, nil, taskID, marker)
	if anonymous.err != nil || anonymous.unsupported || anonymous.matched {
		return nil, fmt.Errorf("%w: anonymous gRPC ListTasks did not establish a private-content control",
			attack.ErrInconclusive)
	}
	cross := grpcListTask(ctx, client, timeout, readerHeaders, taskID, marker)
	if cross.err != nil || cross.unsupported {
		return nil, fmt.Errorf("%w: cross-principal gRPC ListTasks was not judged", attack.ErrInconclusive)
	}
	if cross.found && !cross.matched {
		return nil, fmt.Errorf("%w: cross-principal gRPC ListTasks returned a task without the private marker",
			attack.ErrInconclusive)
	}
	if !cross.matched {
		return nil, nil
	}
	finding := attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "medium", Confidence: attack.RiskIndicator,
		Title: "A2A gRPC task list exposed another tenant's content",
		Description: fmt.Sprintf("Principal %q listed principal %q's marked task over gRPC while GetTask denied the same cross-principal read.",
			reader.Name, owner.Name),
		Evidence:    "owner list: exact task and private marker matched\nanonymous list: private marker absent or denied\ncross GetTask: denied\nreader list: exact task and private marker matched (values omitted)",
		Remediation: e.rule.Remediation, TargetURL: target,
		Access: &attack.AccessObservation{Operation: attack.A2ATasksList, Caller: reader.Name,
			CallerTenant: reader.Tenant, Owner: owner.Name, OwnerTenant: owner.Tenant},
	}
	attack.ApplyExpectedDenial(&finding, denials)
	return []attack.Finding{finding}, nil
}

func (e *GRPCTaskAccessExecutor) checkGRPCSubscribeScope(ctx context.Context, client a2apb.A2AServiceClient,
	timeout time.Duration, target string, owner, reader attack.Principal,
	ownerHeaders, readerHeaders map[string]string, taskID, marker string) ([]attack.Finding, error) {
	owned := grpcSubscribeTask(ctx, client, timeout, ownerHeaders, taskID, marker)
	if owned.err != nil || owned.unsupported || !owned.matched {
		return nil, fmt.Errorf("%w: owner gRPC subscription did not begin with the marked task", attack.ErrInconclusive)
	}
	anonymous := grpcSubscribeTask(ctx, client, timeout, nil, taskID, marker)
	if anonymous.err != nil || anonymous.unsupported || anonymous.found || !anonymous.denied {
		return nil, fmt.Errorf("%w: anonymous gRPC subscription did not establish a private-task control",
			attack.ErrInconclusive)
	}
	cross := grpcSubscribeTask(ctx, client, timeout, readerHeaders, taskID, marker)
	if cross.err != nil || cross.unsupported {
		return nil, fmt.Errorf("%w: cross-principal gRPC subscription was not judged", attack.ErrInconclusive)
	}
	if cross.found && !cross.matched {
		return nil, fmt.Errorf("%w: cross-principal gRPC subscription omitted the private marker",
			attack.ErrInconclusive)
	}
	if !cross.matched {
		return nil, nil
	}
	return []attack.Finding{{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.ConfirmedExploit,
		Title: "A2A gRPC subscription exposed another tenant's task",
		Description: fmt.Sprintf("Principal %q subscribed to principal %q's private task over gRPC after GetTask denied access.",
			reader.Name, owner.Name),
		Evidence:    "owner subscription: exact task and private marker matched\nanonymous subscription: denied\ncross GetTask: denied\nreader subscription: exact task and private marker matched (values omitted)",
		Remediation: e.rule.Remediation, TargetURL: target,
	}}, nil
}
