package mcp

import (
	"context"
	"encoding/json"

	"github.com/calbebop/batesian/internal/attack"
)

const toolListPageCap = 10

// listToolPages returns only complete, correlated listings.
func listToolPages(ctx context.Context, client *attack.HTTPClient, s mcpSession, startID int) ([]json.RawMessage, bool) {
	tools := make([]json.RawMessage, 0)
	seen := map[string]bool{}
	var params map[string]interface{}
	for page := 0; page < toolListPageCap; page++ {
		id := startID + page
		resp, err := s.post(ctx, client, id, "tools/list", params)
		if verdict, _ := classifyProbe(resp, err, id); verdict != probeAnswered {
			return nil, false
		}
		var body struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  *struct {
				ResultType string             `json:"resultType"`
				Tools      *[]json.RawMessage `json:"tools"`
				NextCursor json.RawMessage    `json:"nextCursor"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		var responseID int
		if json.Unmarshal(resp.Body, &body) != nil || body.JSONRPC != "2.0" ||
			json.Unmarshal(body.ID, &responseID) != nil || responseID != id ||
			body.Result == nil || body.Result.Tools == nil || len(body.Error) != 0 ||
			(s.Era == EraModern && body.Result.ResultType != "complete") {
			return nil, false
		}
		tools = append(tools, *body.Result.Tools...)
		if len(body.Result.NextCursor) == 0 {
			return tools, true
		}
		var cursor string
		if string(body.Result.NextCursor) == "null" || json.Unmarshal(body.Result.NextCursor, &cursor) != nil || seen[cursor] {
			return nil, false
		}
		seen[cursor] = true
		params = map[string]interface{}{"cursor": cursor}
	}
	return nil, false
}
