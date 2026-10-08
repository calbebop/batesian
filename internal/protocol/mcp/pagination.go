package mcp

import (
	"context"
	"fmt"
)

func (c *Client) listPages(ctx context.Context, session *Session, id int, method, field string,
	visit func([]interface{}) error) error {
	seen := make(map[string]bool)
	var cursor *string
	for page := 0; page < maxListPages; page++ {
		params := map[string]interface{}{}
		if cursor != nil {
			params["cursor"] = *cursor
		}
		resp, err := c.post(ctx, session, id, method, params)
		if err != nil {
			return fmt.Errorf("%s: %w", method, err)
		}
		result, err := listResult(resp, id, session.Modern)
		if err != nil {
			return fmt.Errorf("%s: %w", method, err)
		}
		items, ok := result[field].([]interface{})
		if !ok {
			return fmt.Errorf("%s result has no %s array", method, field)
		}
		if err := visit(items); err != nil {
			return fmt.Errorf("%s: %w", method, err)
		}
		next, present := result["nextCursor"]
		if !present || next == nil {
			return nil
		}
		token, ok := next.(string)
		if !ok {
			return fmt.Errorf("%s result has an invalid nextCursor", method)
		}
		if seen[token] {
			return fmt.Errorf("%s repeated a pagination cursor", method)
		}
		seen[token] = true
		cursor = &token
	}
	return fmt.Errorf("%s exceeded the %d-page limit", method, maxListPages)
}
