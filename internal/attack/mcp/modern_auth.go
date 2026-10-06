package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/calbebop/batesian/internal/attack"
)

type modernAuthGate struct {
	method string
	ready  bool
}

var modernAuthMethods = []string{"tools/list", "resources/list", "prompts/list", "ping"}

func probeModernAuthGate(ctx context.Context, anon *attack.HTTPClient, ep string) modernAuthGate {
	session := mcpSession{Endpoint: ep, Era: EraModern}
	resp, err := session.post(ctx, anon, 1, "server/discover", nil)
	if err != nil || resp == nil {
		return modernAuthGate{}
	}
	if authRefusal(resp) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp.Headers.Get("WWW-Authenticate"))), "bearer") {
		return modernAuthGate{method: "server/discover", ready: true}
	}
	if !resp.IsAccepted() || !modernWireAdvertised(resp.Body) {
		return modernAuthGate{}
	}
	for _, method := range modernAuthMethods {
		resp, err := session.post(ctx, anon, 2, method, nil)
		if err == nil && authRefusal(resp) {
			return modernAuthGate{method: method, ready: true}
		}
	}
	return modernAuthGate{}
}

func probeModernBearer(ctx context.Context, anon *attack.HTTPClient, ep, method, token string) (*attack.Response, accessVerdict) {
	session := mcpSession{Endpoint: ep, Era: EraModern}
	resp, err := session.postShaping(ctx, anon, 3, method, nil, func(headers map[string]string) {
		headers["Authorization"] = "Bearer " + token
	})
	if err != nil || resp == nil {
		return resp, accessUndetermined
	}
	if resp.IsAccepted() {
		if method != "server/discover" || modernWireAdvertised(resp.Body) {
			return resp, accessGranted
		}
		return resp, accessUndetermined
	}
	if authRefusal(resp) {
		return resp, accessRefused
	}
	return resp, accessUndetermined
}

func authRefusal(resp *attack.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return true
	}
	if !isJSONRPCError(resp.BodyString()) {
		return false
	}
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(resp.Body, &envelope) != nil {
		return false
	}
	message := strings.ToLower(envelope.Error.Message)
	return strings.Contains(message, "unauthorized") ||
		strings.Contains(message, "invalid_token") ||
		strings.Contains(message, "forbidden") ||
		strings.Contains(message, "authentication required")
}
