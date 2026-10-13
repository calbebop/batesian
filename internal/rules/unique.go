package rules

import (
	"fmt"
	"strings"
)

// ValidateUniqueIDs rejects rule IDs that resolve to the same selector.
func ValidateUniqueIDs(catalog []*Rule) error {
	for i, rule := range catalog {
		if rule == nil {
			return fmt.Errorf("nil rule at index %d", i)
		}
		for _, previous := range catalog[:i] {
			if strings.EqualFold(strings.TrimSpace(rule.ID), strings.TrimSpace(previous.ID)) {
				return fmt.Errorf("duplicate rule ID %q conflicts with %q", rule.ID, previous.ID)
			}
		}
	}
	return nil
}
