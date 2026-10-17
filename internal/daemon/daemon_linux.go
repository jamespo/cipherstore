package daemon

import (
	"log"

	"golang.org/x/sys/unix"
)

// disableDumpable clears PR_SET_DUMPABLE so another process running as the
// same user cannot attach with ptrace or read /proc/pid/mem.
func disableDumpable(logger *log.Logger) {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		logger.Printf("warning: could not clear dumpable flag: %v", err)
	}
}
