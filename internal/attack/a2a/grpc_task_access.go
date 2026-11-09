package a2a

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2apb/v1"
	"github.com/calbebop/batesian/internal/attack"
	"github.com/calbebop/batesian/internal/endpoint"
	"github.com/calbebop/batesian/internal/httpx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// GRPCTaskAccessExecutor checks A2A v1.0 gRPC task access in both directions.
type GRPCTaskAccessExecutor struct{ rule attack.RuleContext }

func init() {
	attack.Register("a2a-grpc-task-access", func(rc attack.RuleContext) attack.Executor {
		return NewGRPCTaskAccessExecutor(rc)
	})
}

func NewGRPCTaskAccessExecutor(rc attack.RuleContext) *GRPCTaskAccessExecutor {
	return &GRPCTaskAccessExecutor{rule: rc}
}

func (e *GRPCTaskAccessExecutor) Execute(ctx context.Context, target string, opts attack.Options) ([]attack.Finding, error) {
	if opts.A2AGRPCTarget == "" {
		return nil, fmt.Errorf("%w: configure a2a_grpc_target or --a2a-grpc-target", attack.ErrInconclusive)
	}
	grpcTarget, err := attack.ParseA2AGRPCTarget(opts.A2AGRPCTarget)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", attack.ErrInconclusive, err)
	}
	if opts.Proxy != "" {
		return nil, fmt.Errorf("%w: the A2A gRPC prototype does not support --proxy", attack.ErrInconclusive)
	}
	owner, reader, err := twoPrincipals(opts)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(owner.Tenant) == "" || strings.TrimSpace(reader.Tenant) == "" ||
		strings.EqualFold(strings.TrimSpace(owner.Tenant), strings.TrimSpace(reader.Tenant)) {
		return nil, fmt.Errorf("%w: A2A gRPC task access requires distinct tenant labels", attack.ErrInconclusive)
	}
	ownerHeaders, readerHeaders := principalHeaders(owner), principalHeaders(reader)
	if _, err := grpcCallContext(ctx, ownerHeaders); err != nil {
		return nil, fmt.Errorf("%w: owner gRPC metadata: %v", attack.ErrInconclusive, err)
	}
	if _, err := grpcCallContext(ctx, readerHeaders); err != nil {
		return nil, fmt.Errorf("%w: reader gRPC metadata: %v", attack.ErrInconclusive, err)
	}
	vars := attack.NewVars(target, opts.OOBListenerURL)
	if opts.DryRun {
		cardHeaders := make(map[string]string, len(owner.Headers)+1)
		for name, value := range owner.Headers {
			cardHeaders[name] = value
		}
		cardHeaders["A2A-Version"] = "1.0"
		_, _ = principalClient(opts, vars, owner).GET(ctx,
			endpoint.AppendPath(vars.BaseURL, cardPathPrimary), cardHeaders)
		if opts.Recorder != nil {
			for _, method := range []string{"SendMessage", "SendMessage", "GetTask", "GetTask", "GetTask", "GetTask", "GetTask", "GetTask"} {
				opts.Recorder.RecordGRPC(opts.A2AGRPCTarget, method)
			}
		}
		return nil, nil
	}
	card, ok := grpcDiscoveryCard(ctx, principalClient(opts, vars, owner), vars.BaseURL, owner.Headers)
	if !ok || !grpcCardMatches(card, grpcTarget) {
		return nil, fmt.Errorf("%w: no unambiguous advertised A2A v1.0 gRPC interface matches %s",
			attack.ErrInconclusive, grpcTarget.Address)
	}
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 10
	}
	requestTimeout, err := httpx.TimeoutDuration(opts.TimeoutSeconds)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid gRPC request timeout: %v", attack.ErrInconclusive, err)
	}
	conn, err := dialA2AGRPC(grpcTarget, opts.SkipTLS)
	if err != nil {
		return nil, fmt.Errorf("%w: could not initialize A2A gRPC client: %v", attack.ErrInconclusive, err)
	}
	defer conn.Close()
	client := a2apb.NewA2AServiceClient(conn)
	ownerMarker := "batesian grpc owner " + vars.RandID
	readerMarker := "batesian grpc reader " + vars.RandID
	ownerTask, err := grpcCreateTask(ctx, client, requestTimeout, ownerHeaders, ownerMarker, vars.RandID+"-owner")
	if err != nil {
		return nil, err
	}
	readerTask, err := grpcCreateTask(ctx, client, requestTimeout, readerHeaders, readerMarker, vars.RandID+"-reader")
	if err != nil {
		return nil, err
	}
	if ownerTask == readerTask {
		return nil, fmt.Errorf("%w: both principals received the same gRPC task ID", attack.ErrInconclusive)
	}
	ownerRead := grpcReadTask(ctx, client, requestTimeout, ownerHeaders, ownerTask, ownerMarker)
	readerRead := grpcReadTask(ctx, client, requestTimeout, readerHeaders, readerTask, readerMarker)
	if ownerRead.location == "" || readerRead.location == "" {
		return nil, fmt.Errorf("%w: the task owner or second principal could not read its own gRPC probe text",
			attack.ErrInconclusive)
	}
	var findings []attack.Finding
	var incomplete error
	for _, direction := range []struct {
		owner, reader  attack.Principal
		readerHeaders  map[string]string
		taskID, marker string
	}{
		{owner, reader, readerHeaders, ownerTask, ownerMarker},
		{reader, owner, ownerHeaders, readerTask, readerMarker},
	} {
		anonymous := grpcReadTask(ctx, client, requestTimeout, nil, direction.taskID, direction.marker)
		if anonymous.location != "" {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: %s's gRPC task is publicly readable; tenant attribution is not established",
				attack.ErrInconclusive, direction.owner.Name))
			continue
		}
		if !anonymous.denied || anonymous.unknown {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: anonymous gRPC read of %s's task was not explicitly denied",
				attack.ErrInconclusive, direction.owner.Name))
			continue
		}
		cross := grpcReadTask(ctx, client, requestTimeout, direction.readerHeaders, direction.taskID, direction.marker)
		if cross.location != "" {
			findings = append(findings, e.finding(opts.A2AGRPCTarget, direction.owner, direction.reader, cross))
			continue
		}
		if !cross.denied || cross.unknown {
			incomplete = errors.Join(incomplete, fmt.Errorf("%w: %s's gRPC read of %s's task was not judged",
				attack.ErrInconclusive, direction.reader.Name, direction.owner.Name))
		}
	}
	return findings, incomplete
}

func grpcDiscoveryCard(ctx context.Context, client *attack.HTTPClient, base string,
	extraHeaders map[string]string) (a2aDiscoveryCard, bool) {
	cardURL := endpoint.AppendPath(base, cardPathPrimary)
	for _, versioned := range []bool{true, false} {
		headers := make(map[string]string, len(extraHeaders)+1)
		for name, value := range extraHeaders {
			headers[name] = value
		}
		if versioned {
			headers["A2A-Version"] = "1.0"
		}
		resp, err := client.GET(ctx, cardURL, headers)
		if err != nil || resp == nil || !resp.IsSuccess() || !resp.IsJSON() {
			continue
		}
		var card a2aDiscoveryCard
		if json.Unmarshal(resp.Body, &card) == nil && len(card.SupportedInterfaces) > 0 {
			return card, true
		}
	}
	return a2aDiscoveryCard{}, false
}

func grpcCardMatches(card a2aDiscoveryCard, target attack.A2AGRPCTarget) bool {
	matched, scoped := false, false
	for _, iface := range card.SupportedInterfaces {
		if !strings.EqualFold(iface.ProtocolBinding, "GRPC") || iface.ProtocolVersion != "1.0" {
			continue
		}
		address, scheme := grpcCardAddress(iface.URL)
		if address != target.Address ||
			((scheme == "https" || scheme == "grpcs") != target.Secure) {
			continue
		}
		if iface.Tenant != nil {
			scoped = true
		} else {
			matched = true
		}
	}
	return matched && !scoped
}

func grpcCardAddress(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != "" && u.Path != "/" ||
		u.Scheme != "https" && u.Scheme != "grpcs" &&
			u.Scheme != "http" && u.Scheme != "grpc" {
		return "", ""
	}
	host, port := u.Hostname(), u.Port()
	if port == "" && (u.Scheme == "https" || u.Scheme == "grpcs") {
		port = "443"
	}
	if port == "" && (u.Scheme == "http" || u.Scheme == "grpc") {
		port = "80"
	}
	portNumber, err := strconv.Atoi(port)
	if host == "" || err != nil || portNumber < 1 || portNumber > 65535 {
		return "", ""
	}
	return net.JoinHostPort(strings.ToLower(host), port), u.Scheme
}

func dialA2AGRPC(target attack.A2AGRPCTarget, skipTLS bool) (*grpc.ClientConn, error) {
	var transport credentials.TransportCredentials
	if target.Secure {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if skipTLS {
			config.InsecureSkipVerify = true //nolint:gosec
		}
		transport = credentials.NewTLS(config)
	} else {
		transport = insecure.NewCredentials()
	}
	return grpc.NewClient(target.Address,
		grpc.WithTransportCredentials(transport), grpc.WithDisableRetry(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1<<20), grpc.MaxCallSendMsgSize(1<<20)))
}

func grpcCallContext(ctx context.Context, headers map[string]string) (context.Context, error) {
	md := metadata.Pairs("a2a-version", "1.0")
	for name, value := range headers {
		key := strings.ToLower(name)
		if key == "a2a-version" {
			continue
		}
		if key == "" || strings.HasPrefix(key, "grpc-") || strings.HasPrefix(key, ":") ||
			strings.Trim(key, "abcdefghijklmnopqrstuvwxyz0123456789-_.") != "" {
			return nil, fmt.Errorf("invalid gRPC metadata key %q", name)
		}
		for _, c := range value {
			if c < 32 || c > 126 {
				return nil, fmt.Errorf("invalid gRPC metadata value for %q", name)
			}
		}
		md.Set(key, value)
	}
	return metadata.NewOutgoingContext(ctx, md), nil
}

func grpcCreateTask(ctx context.Context, client a2apb.A2AServiceClient, timeout time.Duration,
	headers map[string]string, marker, messageID string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	callCtx, err := grpcCallContext(callCtx, headers)
	if err != nil {
		return "", fmt.Errorf("%w: %v", attack.ErrInconclusive, err)
	}
	resp, err := client.SendMessage(callCtx, &a2apb.SendMessageRequest{
		Message: &a2apb.Message{MessageId: messageID, Role: a2apb.Role_ROLE_USER,
			Parts: []*a2apb.Part{{Content: &a2apb.Part_Text{Text: marker}}}},
		Configuration: &a2apb.SendMessageConfiguration{ReturnImmediately: true},
	})
	if err != nil || resp.GetTask().GetId() == "" {
		return "", fmt.Errorf("%w: A2A gRPC SendMessage did not create a task (status %s)",
			attack.ErrInconclusive, status.Code(err))
	}
	return resp.GetTask().GetId(), nil
}

func grpcReadTask(ctx context.Context, client a2apb.A2AServiceClient, timeout time.Duration,
	headers map[string]string, taskID, marker string) tenantRead {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	callCtx, err := grpcCallContext(callCtx, headers)
	if err != nil {
		return tenantRead{unknown: true}
	}
	historyLength := int32(10)
	task, err := client.GetTask(callCtx, &a2apb.GetTaskRequest{Id: taskID, HistoryLength: &historyLength})
	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated, codes.PermissionDenied, codes.NotFound:
			return tenantRead{denied: true}
		default:
			return tenantRead{unknown: true}
		}
	}
	if task == nil {
		return tenantRead{unknown: true}
	}
	body, err := protojson.Marshal(task)
	if err != nil {
		return tenantRead{unknown: true}
	}
	location, matched := taskMarkerLocation(body, taskID, marker)
	return tenantRead{method: "gRPC GetTask", location: location, matched: matched,
		unknown: location == ""}
}

func (e *GRPCTaskAccessExecutor) finding(target string, owner, reader attack.Principal,
	read tenantRead) attack.Finding {
	return attack.Finding{
		RuleID: e.rule.ID, RuleName: e.rule.Name, Severity: "high", Confidence: attack.ConfirmedExploit,
		Title: "A2A gRPC disclosed another tenant's task content",
		Description: fmt.Sprintf("Principal %q (tenant %q) read principal %q's (tenant %q) task over gRPC. Both principals could read their own tasks, while the anonymous control was denied.",
			reader.Name, reader.Tenant, owner.Name, owner.Tenant),
		Evidence: fmt.Sprintf("target: %s\nowner: %s (tenant %s)\nreader: %s (tenant %s)\nowner task and probe text: matched (values omitted)\nlocation: %s\nanonymous: denied",
			target, owner.Name, owner.Tenant, reader.Name, reader.Tenant, read.location),
		Remediation: e.rule.Remediation, TargetURL: target,
		Chain: []attack.ChainStep{
			{Hop: 1, Principal: owner.Name, Action: "create and read gRPC task", Outcome: "read probe text"},
			{Hop: 2, Principal: reader.Name, Action: "create and read own gRPC task", Outcome: "read control text"},
			{Hop: 3, Principal: reader.Name, Action: "read owner task over gRPC", Outcome: "read owner's probe text"},
		},
	}
}

var _ attack.Executor = (*GRPCTaskAccessExecutor)(nil)
