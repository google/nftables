package nftest

import (
	"fmt"
	"math"
	"runtime"

	"golang.org/x/sys/unix"
)

// AsUnprivileged temporarily drops the effective UID to an unprivileged
// value (65535) while executing the provided function. It requires the
// process to be running as root to be able to regain privileges afterwards.
func AsUnprivileged(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	targetUID := math.MaxUint16
	_, euid, suid := unix.Getresuid()

	if euid != 0 && suid != 0 {
		return fmt.Errorf("must be run as root to regain privileges (euid=%d suid=%d)", euid, suid)
	}

	// Drop privileges by changing only the effective UID
	if err := unix.Setresuid(-1, targetUID, -1); err != nil {
		return fmt.Errorf("failed to drop effective UID to %d: %w", targetUID, err)
	}

	// Restore when done
	defer func() {
		if err := unix.Setresuid(-1, euid, -1); err != nil {
			panic(fmt.Sprintf("failed to restore euid=%d: %v", euid, err))
		}
	}()

	return fn()
}
