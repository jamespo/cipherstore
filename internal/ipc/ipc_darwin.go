package ipc

import "golang.org/x/sys/unix"

// peerCred reads the UID and group IDs of the process on the other end of a
// unix socket fd.
//
// Darwin has no SO_PEERCRED; LOCAL_PEERCRED at SOL_LOCAL is its equivalent,
// returning a struct xucred rather than ucred. Its group list holds at most 16
// entries, the first being the effective group.
func peerCred(fd int, withGroups bool) (uint32, []uint32, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, nil, err
	}
	if !withGroups {
		return cred.Uid, nil, nil
	}
	n := int(cred.Ngroups)
	if n < 0 || n > len(cred.Groups) {
		n = len(cred.Groups)
	}
	return cred.Uid, append([]uint32(nil), cred.Groups[:n]...), nil
}
