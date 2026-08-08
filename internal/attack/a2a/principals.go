package a2a

import (
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

// twoPrincipals returns the two identities a cross-principal rule needs, or an
// error saying why the rule cannot run.
//
// Five rules carried this precondition and all five answered it with nil,nil,
// which under this project's convention means "tested, and the target is secure".
// They send no packets in that state. So a default invocation, with no --principal
// flags, reported a2a-multitenant-isolation-001,
// a2a-delegation-integrity-001, a2a-context-fixation-001, a2a-push-binding-001 and
// a2a-task-cancel-idor-001 as clean: 5 of 17 A2A rules, 29 percent of the set,
// silently self-disabling while the operator was told the target appeared clean for
// the tested rules. Measured against testdata/a2a_multitenant_server.py, which is
// deliberately vulnerable: 5 rules run, zero requests, "No findings. Target appears
// clean for the tested rules."
//
// Two distinct credentials are the whole premise of these rules. Without them there
// is no second authorization context to cross, which is a reason the rule could not
// run and not a property of the target.
func twoPrincipals(opts attack.Options) (a, b attack.Principal, err error) {
	if len(opts.Principals) < 2 {
		return a, b, fmt.Errorf("%w: this rule compares two authenticated identities and %d "+
			"were configured; pass two --principal flags (or a config with two principals) to run it",
			attack.ErrInconclusive, len(opts.Principals))
	}
	a, b = opts.Principals[0], opts.Principals[1]
	if a.Token == b.Token {
		return a, b, fmt.Errorf("%w: principals %q and %q carry the same token, so there is no "+
			"second authorization context for this rule to cross",
			attack.ErrInconclusive, a.Name, b.Name)
	}
	return a, b, nil
}
