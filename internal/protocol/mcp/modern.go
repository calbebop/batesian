package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const modernVersion = "2026-07-28"

func modernMeta() map[string]interface{} {
	return map[string]interface{}{
		"io.modelcontextprotocol/protocolVersion": modernVersion,
		"io.modelcontextprotocol/clientInfo": map[string]interface{}{
			"name": "batesian", "version": "1.0",
		},
		"io.modelcontextprotocol/clientCapabilities": map[string]interface{}{},
	}
}

func (c *Client) newRPCRequest(ctx context.Context, endpoint string, id interface{}, method string,
	params map[string]interface{}, modern bool) (*http.Request, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if modern {
		withMeta := make(map[string]interface{}, len(params)+1)
		for key, value := range params {
			withMeta[key] = value
		}
		withMeta["_meta"] = modernMeta()
		params = withMeta
	}
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	})
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, endpoint, body)
	if err != nil {
		return nil, err
	}
	if modern {
		req.Header.Set("MCP-Protocol-Version", modernVersion)
		req.Header.Set("Mcp-Method", method)
	}
	return req, nil
}

func (c *Client) tryDiscover(ctx context.Context, endpoint string) (*Session, error) {
	const requestID = "batesian-probe-discover"
	req, err := c.newRPCRequest(ctx, endpoint, requestID, "server/discover", nil, true)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("modern MCP discovery authorization refused: HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed ||
			resp.StatusCode == http.StatusNotImplemented {
			return nil, fmt.Errorf("%w: HTTP %d", errModernUnavailable, resp.StatusCode)
		}
		if resp.StatusCode == http.StatusBadRequest {
			raw, readErr := readBody(resp)
			if readErr != nil {
				return nil, readErr
			}
			if legacyDiscoveryError(raw) {
				return nil, fmt.Errorf("%w: discovery RPC rejected", errModernUnavailable)
			}
		}
		return nil, fmt.Errorf("modern MCP discovery returned HTTP %d", resp.StatusCode)
	}
	raw, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("non-JSON modern MCP discovery response: %w", err)
	}
	if envelope["jsonrpc"] != "2.0" || envelope["id"] != requestID {
		return nil, fmt.Errorf("invalid modern MCP discovery response")
	}
	if _, ok := envelope["error"]; ok {
		if legacyDiscoveryError(raw) {
			return nil, fmt.Errorf("%w: discovery RPC rejected", errModernUnavailable)
		}
		return nil, fmt.Errorf("modern MCP discovery RPC error")
	}
	result, ok := envelope["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" {
		return nil, fmt.Errorf("missing complete modern MCP discovery result")
	}
	versions, ok := result["supportedVersions"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing supportedVersions in modern MCP discovery")
	}
	supported := false
	for _, version := range versions {
		if version == modernVersion {
			supported = true
			break
		}
	}
	if !supported {
		return nil, fmt.Errorf("%w: MCP %s not advertised", errModernUnavailable, modernVersion)
	}
	caps, ok := result["capabilities"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing capabilities in modern MCP discovery")
	}
	meta, _ := result["_meta"].(map[string]interface{})
	info, _ := meta["io.modelcontextprotocol/serverInfo"].(map[string]interface{})
	return &Session{
		Endpoint:        endpoint,
		ProtocolVersion: modernVersion,
		Modern:          true,
		ServerInfo: ServerInfo{
			Name:    strField(info, "name"),
			Version: strField(info, "version"),
			Title:   strField(info, "title"),
		},
		Capabilities: caps,
	}, nil
}

func legacyDiscoveryError(raw []byte) bool {
	var envelope struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return false
	}
	return envelope.Error.Code == -32601 || envelope.Error.Code == -32022
}
