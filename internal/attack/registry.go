package attack

import (
	"fmt"
	"sort"
)

// Constructor builds an Executor for a given rule context. Each attack
// implementation registers a Constructor under its attack-type string.
type Constructor func(RuleContext) Executor

// registry maps an attack-type string (the rule's attack.type field) to the
// Constructor that builds its Executor. Implementations register themselves in
// an init() function so adding a check is a single self-contained file rather
// than an edit to a central switch statement.
var registry = map[string]Constructor{}

// Register associates an attack-type string with its Executor constructor.
// It panics on duplicate registration, which can only happen via a programming
// error (two executors claiming the same type) and is caught at startup.
func Register(attackType string, c Constructor) {
	if attackType == "" {
		panic("attack.Register: empty attack type")
	}
	if c == nil {
		panic(fmt.Sprintf("attack.Register: nil constructor for %q", attackType))
	}
	if _, dup := registry[attackType]; dup {
		panic(fmt.Sprintf("attack.Register: duplicate attack type %q", attackType))
	}
	registry[attackType] = c
}

// Resolve returns the Constructor registered for attackType, if any.
func Resolve(attackType string) (Constructor, bool) {
	c, ok := registry[attackType]
	return c, ok
}

// RegisteredTypes returns the sorted list of all registered attack types.
// Useful for diagnostics and for validating that every shipped rule has a
// matching executor.
func RegisteredTypes() []string {
	types := make([]string, 0, len(registry))
	for t := range registry {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}
