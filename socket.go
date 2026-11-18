package nftables

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// isReadReady reports whether the netlink connection is ready for reading.
// It uses poll(2) with a zero timeout on the underlying raw connection.
// This allows for an efficient check of socket readiness without blocking.
// If the Conn was created with a TestDial function, it assumes readiness.
func (cc *Conn) isReadReady(conn *netlink.Conn) (bool, error) {
	if cc.TestDial != nil {
		return true, nil
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false, fmt.Errorf("get raw conn: %w", err)
	}

	var n int
	var opErr error
	err = rawConn.Control(func(fd uintptr) {
		fds := []unix.PollFd{{
			Fd:     int32(fd),
			Events: unix.POLLIN,
		}}
		for {
			n, opErr = unix.Poll(fds, 0) // 0 timeout: immediate return
			if opErr != unix.EINTR {
				break
			}
		}
	})
	if err != nil {
		return false, err
	}

	if opErr != nil {
		return false, fmt.Errorf("poll: %w", opErr)
	}

	return n > 0, nil
}
