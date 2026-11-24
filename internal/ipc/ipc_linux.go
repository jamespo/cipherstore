package ipc

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// soPeerGroups is Linux's SO_PEERGROUPS (since 4.13), which golang.org/x/sys
// does not define. 59 is its value on the asm-generic ABI used by amd64 and
// arm64, the architectures cipherstore is built for.
const soPeerGroups = 59

// maxPeerGroups bounds the group list we will read; NGROUPS_MAX is 65536.
const maxPeerGroups = 65536

// peerCred reads the UID of the process on the other end of a unix socket fd
// via SO_PEERCRED and, when withGroups is set, its primary and supplementary
// group IDs via SO_PEERGROUPS. Both are the credentials the peer had when it
// connected, recorded by the kernel.
func peerCred(fd int, withGroups bool) (uint32, []uint32, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, nil, err
	}
	if !withGroups {
		return cred.Uid, nil, nil
	}
	groups, err := peerGroups(fd)
	if err != nil {
		return 0, nil, err
	}
	return cred.Uid, append(groups, cred.Gid), nil
}

func peerGroups(fd int) ([]uint32, error) {
	buf := make([]uint32, 64)
	for {
		size := uint32(len(buf) * 4)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
			unix.SOL_SOCKET, soPeerGroups,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch {
		case errno == 0:
			return buf[:size/4], nil
		case errno == unix.ERANGE && size/4 > uint32(len(buf)) && size/4 <= maxPeerGroups:
			// The kernel reports the size it needs; retry with that.
			buf = make([]uint32, size/4)
		default:
			return nil, errno
		}
	}
}
