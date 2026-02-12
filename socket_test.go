package nftables_test

import (
	"os"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/internal/nftest"
	"golang.org/x/sys/unix"
)

// TestIsReadReadyHighFD verifies that the nftables library works correctly when
// the underlying netlink socket gets an fd >= FD_SETSIZE (1024). The old
// pselect-based implementation would panic in this scenario because
// unix.FdSet.Set panics for fd >= FD_SETSIZE. The current poll-based
// implementation has no such limit.
func TestIsReadReadyHighFD(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	// Exhaust low file descriptors so the next socket allocation gets fd >= FD_SETSIZE.
	var fillers []*os.File
	defer func() {
		for _, f := range fillers {
			f.Close()
		}
	}()

	for {
		f, err := os.Open("/dev/null")
		if err != nil {
			t.Fatalf("os.Open(/dev/null): %v", err)
		}
		fillers = append(fillers, f)
		if int(f.Fd()) >= unix.FD_SETSIZE {
			break
		}
	}
	t.Logf("exhausted fds up to %d", fillers[len(fillers)-1].Fd())

	// By default, a transient socket is created for each request. The socket
	// will get an fd >= FD_SETSIZE. With the old pselect code this would panic;
	// with poll it must work.

	// Add a command and flush it to trigger the isReadReady code path.
	c.AddTable(&nftables.Table{Name: "test_high_fd", Family: nftables.TableFamilyIPv4})
	func() {
		// turn the potential panic into a test failure.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("isReadReady panicked for fd >= %d: %v", unix.FD_SETSIZE, r)
			}
		}()
		if err := c.Flush(); err != nil {
			t.Fatalf("Flush() failed: %v", err)
		}
	}()
}
