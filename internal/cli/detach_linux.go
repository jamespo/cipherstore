package cli

import "syscall"

// sysDetach puts the daemon in a new session, detached from the launching
// shell's controlling terminal.
func sysDetach() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
