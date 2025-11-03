package nftables

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// isReadReady reports whether the netlink connection is ready for reading.
// It uses pselect6 with a zero timeout on the underlying raw connection.
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
		var readfds unix.FdSet
		readfds.Zero()
		readfds.Set(int(fd))

		ts := &unix.Timespec{} // zero timeout: immediate return
		n, opErr = unix.Pselect(int(fd)+1, &readfds, nil, nil, ts, nil)
	})
	if err != nil {
		return false, err
	}

	return n > 0, opErr
}
