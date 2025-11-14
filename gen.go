package nftables

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type Gen struct {
	ID       uint32
	ProcPID  uint32
	ProcComm string // [16]byte - max 16bytes - kernel TASK_COMM_LEN
}

// Deprecated: GenMsg is an inconsistent old name for Gen. Prefer using Gen.
type GenMsg = Gen

var genHeaderType = nftMsgNewGen.HeaderType()

func genFromMsg(msg netlink.Message) (*Gen, error) {
	if got, want := msg.Header.Type, genHeaderType; got != want {
		return nil, fmt.Errorf("unexpected header type: got %v, want %v", got, want)
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian

	msgOut := &Gen{}
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_GEN_ID:
			msgOut.ID = ad.Uint32()
		case unix.NFTA_GEN_PROC_PID:
			msgOut.ProcPID = ad.Uint32()
		case unix.NFTA_GEN_PROC_NAME:
			msgOut.ProcComm = ad.String()
		default:
			return nil, fmt.Errorf("unknown attribute: %d, %v", ad.Type(), ad.Bytes())
		}
	}
	if err := ad.Err(); err != nil {
		return nil, err
	}
	return msgOut, nil
}

// GetGen retrieves the current nftables generation ID together with the name
// and ID of the process that last modified the ruleset.
// https://docs.kernel.org/networking/netlink_spec/nftables.html#getgen
func (cc *Conn) GetGen() (*Gen, error) {
	conn, closer, err := cc.netlinkConn()
	if err != nil {
		return nil, err
	}
	defer func() { _ = closer() }()

	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_GEN_ID},
	})
	if err != nil {
		return nil, err
	}

	message := netlink.Message{
		Header: netlink.Header{
			Type:  nftMsgGetGen.HeaderType(),
			Flags: netlink.Request,
		},
		Data: append(extraHeader(0, 0), data...),
	}

	if _, err := conn.SendMessages([]netlink.Message{message}); err != nil {
		return nil, fmt.Errorf("SendMessages: %v", err)
	}

	reply, err := cc.receive(conn)
	if err != nil {
		return nil, fmt.Errorf("receive: %v", err)
	}
	if len(reply) == 0 {
		return nil, fmt.Errorf("receive: no reply")
	}
	return genFromMsg(reply[0])
}
