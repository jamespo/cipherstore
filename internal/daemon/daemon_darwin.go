package daemon

import "log"

// disableDumpable is a no-op on Darwin: golang.org/x/sys/unix exposes no
// equivalent of Linux's PR_SET_DUMPABLE. Core dumps are still disabled via
// RLIMIT_CORE regardless.
func disableDumpable(logger *log.Logger) {
	logger.Print("notice: ptrace hardening (PR_SET_DUMPABLE) has no equivalent on this platform; skipping")
}
