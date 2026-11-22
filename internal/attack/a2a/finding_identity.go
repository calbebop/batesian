package a2a

import (
	"fmt"

	"github.com/calbebop/batesian/internal/attack"
)

func accessFindingIdentity(kind string, owner, caller attack.Principal) string {
	return fmt.Sprintf("%q:%q:%q:%q:%q", kind, owner.Name, owner.Tenant, caller.Name, caller.Tenant)
}
