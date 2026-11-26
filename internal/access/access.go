// Package access defines who may talk to a cipherstore daemon.
//
// The policy decides the permissions on the socket directory and the sockets,
// and which peers the daemon accepts once they connect. The filesystem
// permissions are the main gate: a user who cannot search the directory or
// write the socket cannot connect at all. The peer-credential check in package
// ipc then repeats the same decision, using what the kernel reports about the
// connecting process.
//
// The database directory is not covered by this policy. Only the daemon opens
// the database, so that directory always stays owner-only.
package access

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Mode selects how widely the daemon's sockets are shared.
type Mode int

const (
	// Solo allows only the user running the daemon. It is the zero value, so
	// an unset Policy is the most restrictive one.
	Solo Mode = iota
	// Group also allows members of one unix group.
	Group
	// All allows every local user.
	All
)

// ParseMode parses the -mode flag value.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "solo", "":
		return Solo, nil
	case "group":
		return Group, nil
	case "all":
		return All, nil
	default:
		return Solo, fmt.Errorf("invalid mode %q (want solo, group or all)", s)
	}
}

func (m Mode) String() string {
	switch m {
	case Solo:
		return "solo"
	case Group:
		return "group"
	case All:
		return "all"
	default:
		return fmt.Sprintf("Mode(%d)", int(m))
	}
}

// Policy is a Mode plus, for Group, the group that is let in, and what users
// other than the daemon's owner may do once connected.
type Policy struct {
	Mode Mode
	// GID is the group allowed in Group mode. Other modes ignore it.
	GID int
	// FullAccess lets users other than the owner list, export, import, add and
	// delete secrets. Without it they may only get secrets and ask for the
	// status. Solo mode ignores it, since only the owner can connect.
	FullAccess bool
}

// DirPerm is the mode the socket directory is given.
//
// No mode gives write permission to anyone except the owner. Write access to
// the directory would let another user delete the sockets and put their own
// in place.
func (p Policy) DirPerm() os.FileMode {
	switch p.Mode {
	case Group:
		return 0o750
	case All:
		return 0o755
	default:
		return 0o700
	}
}

// SocketPerm is the mode the sockets are given. A client needs write
// permission on a unix socket to connect to it.
func (p Policy) SocketPerm() os.FileMode {
	switch p.Mode {
	case Group:
		return 0o770
	case All:
		return 0o777
	default:
		return 0o700
	}
}

func (p Policy) String() string {
	s := p.Mode.String()
	if p.Mode == Group {
		s = fmt.Sprintf("group (gid %d)", p.GID)
	}
	if p.Mode == Solo {
		return s
	}
	if p.FullAccess {
		return s + ", full access"
	}
	return s + ", get only"
}

// LookupGroup resolves a group name, or a numeric gid, to a gid.
func LookupGroup(name string) (int, error) {
	if g, err := user.LookupGroup(name); err == nil {
		return strconv.Atoi(g.Gid)
	}
	if g, err := user.LookupGroupId(name); err == nil {
		return strconv.Atoi(g.Gid)
	}
	return 0, fmt.Errorf("unknown group %q", name)
}
