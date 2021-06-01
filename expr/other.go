package expr

import (
	"encoding/binary"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Other is a nft expression that this library don't know
// It can unmarshal/marshal it as list of attributes
type Other struct {
	Type       string // the type (name) of the expression
	Attributes []OtherAttribute
}

// OtherAttribute is one of the attributes in an Other
type OtherAttribute struct {
	Type uint16
	Data []byte
}

func (e *Other) marshal() ([]byte, error) {
	attrs := make([]netlink.Attribute, len(e.Attributes))
	for i, a := range e.Attributes {
		attrs[i].Type = a.Type
		attrs[i].Data = a.Data
	}

	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte(e.Type + "\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Other) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		e.Attributes = append(e.Attributes, OtherAttribute{Type: ad.Type(), Data: ad.Bytes()})
	}
	return ad.Err()
}
