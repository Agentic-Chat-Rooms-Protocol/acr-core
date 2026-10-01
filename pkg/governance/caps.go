package governance

import (
	"errors"
	"fmt"
	"strings"
)

// Caps represents a 10-bit capability bitmask.
type Caps uint32

const (
	CapRead        Caps = 1 << 0 // 0x0001
	CapPost        Caps = 1 << 1 // 0x0002
	CapCreateBoard Caps = 1 << 2 // 0x0004
	CapEditOwn     Caps = 1 << 3 // 0x0008
	CapModerate    Caps = 1 << 4 // 0x0010
	CapFederate    Caps = 1 << 5 // 0x0020
	CapPlugins     Caps = 1 << 6 // 0x0040
	CapMarketplace Caps = 1 << 7 // 0x0080
	CapSysop       Caps = 1 << 8 // 0x0100
	CapMcpEgress   Caps = 1 << 9 // 0x0200

	// AllCaps is the full 10-bit mask.
	AllCaps Caps = 0x03FF
)

// DefaultCaps returns the least-privilege default for anonymous agents: READ | POST | EDIT_OWN.
func DefaultCaps() Caps {
	return CapRead | CapPost | CapEditOwn // 0x000B
}

// Role defines conventional monotonic bundles of capability bits.
type Role string

const (
	RoleGuest     Role = "guest"
	RoleAgent     Role = "agent"
	RoleModerator Role = "moderator"
	RoleFederator Role = "federator"
	RoleSysop     Role = "sysop"
)

// Caps returns the bitmask bundle granted by this role.
func (r Role) Caps() Caps {
	switch strings.ToLower(string(r)) {
	case string(RoleGuest):
		return CapRead
	case string(RoleAgent):
		return DefaultCaps() | CapPlugins | CapMarketplace | CapMcpEgress // 0x02CB
	case string(RoleModerator):
		return RoleAgent.Caps() | CapModerate | CapCreateBoard // 0x02DF
	case string(RoleFederator):
		return RoleModerator.Caps() | CapFederate // 0x02FF
	case string(RoleSysop):
		return AllCaps // 0x03FF
	default:
		return DefaultCaps()
	}
}

// HasCap checks if the held bitmask contains all bits in the needed bitmask.
func HasCap(held, needed Caps) bool {
	return (held & needed) == needed
}

// RequireCap returns an error if held does not contain needed capabilities.
func RequireCap(held, needed Caps, opName string) error {
	if HasCap(held, needed) {
		return nil
	}
	return fmt.Errorf("permission denied for %s: missing capability (held=0x%04X, needed=0x%04X)", opName, held, needed)
}

var ErrPermissionDenied = errors.New("permission denied: insufficient capabilities")
