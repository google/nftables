package expr

import (
	"bytes"
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// See https://git.netfilter.org/libnftnl/tree/src/expr/match.c?id=09456c720e9c00eecc08e41ac6b7c291b3821ee5#n30
type Match struct {
	Name string
	Rev  uint32
	Info []byte
}

func (e *Match) marshal() ([]byte, error) {
	// Per https://git.netfilter.org/libnftnl/tree/src/expr/match.c?id=09456c720e9c00eecc08e41ac6b7c291b3821ee5#n38
	name := e.Name
	// limit the extension name as (some) user-space tools do and leave room for
	// trailing \x00
	if len(name) >= /* sic! */ XTablesExtensionNameMaxLen {
		name = name[:XTablesExtensionNameMaxLen-1] // leave room for trailing \x00.
	}
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_MATCH_NAME, Data: []byte(name + "\x00")},
		{Type: unix.NFTA_MATCH_REV, Data: binaryutil.BigEndian.PutUint32(e.Rev)},
		{Type: unix.NFTA_MATCH_INFO, Data: e.Info},
	}
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("match\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Match) unmarshal(data []byte) error {
	// Per https://git.netfilter.org/libnftnl/tree/src/expr/match.c?id=09456c720e9c00eecc08e41ac6b7c291b3821ee5#n65
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_MATCH_NAME:
			// We are forgiving here, accepting any length and even missing terminating \x00.
			e.Name = string(bytes.TrimRight(ad.Bytes(), "\x00"))
		case unix.NFTA_MATCH_REV:
			e.Rev = ad.Uint32()
		case unix.NFTA_MATCH_INFO:
			e.Info = ad.Bytes()
		}
	}
	return ad.Err()
}
