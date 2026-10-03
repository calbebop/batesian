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
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, endpoint)
	}
	raw, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("non-JSON discovery response from %s: %w", endpoint, err)
	}
	if envelope["jsonrpc"] != "2.0" || envelope["id"] != requestID {
		return nil, fmt.Errorf("invalid discovery response from %s", endpoint)
	}
	result, ok := envelope["result"].(map[string]interface{})
	if !ok || result["resultType"] != "complete" {
		return nil, fmt.Errorf("missing complete discovery result from %s", endpoint)
	}
	versions, ok := result["supportedVersions"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing supportedVersions from %s", endpoint)
	}
	supported := false
	for _, version := range versions {
		if version == modernVersion {
			supported = true
			break
		}
	}
	if !supported {
		return nil, fmt.Errorf("%s does not advertise MCP %s", endpoint, modernVersion)
	}
	caps, ok := result["capabilities"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing capabilities from %s", endpoint)
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
