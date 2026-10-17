package ipc

import "golang.org/x/sys/unix"

// peerUID reads the UID of the process on the other end of a unix socket fd.
//
// Darwin has no SO_PEERCRED; LOCAL_PEERCRED at SOL_LOCAL is its equivalent,
// returning a struct xucred rather than ucred.
func peerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}
