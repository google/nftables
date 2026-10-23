// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Not yet supported by unix package
// https://cs.opensource.google/go/x/sys/+/c6bc011c:unix/ztypes_linux.go;l=1986-1991
const (
	NFTA_BITWISE_OP    = 0x6
	NFTA_BITWISE_DATA  = 0x7
	NFTA_BITWISE_SREG2 = 0x8
)

type BitwiseOp uint32

const (
	BitwiseOpMaskXor BitwiseOp = 0x0
	BitwiseOpLshift  BitwiseOp = 0x1
	BitwiseOpRshift  BitwiseOp = 0x2
	BitwiseOpAnd     BitwiseOp = 0x3
	BitwiseOpOr      BitwiseOp = 0x4
	BitwiseOpXor     BitwiseOp = 0x5
)

type Bitwise struct {
	SourceRegister  uint32
	SourceRegister2 uint32
	DestRegister    uint32
	Len             uint32
	Mask            []byte
	Xor             []byte
	Data            []byte
	Op              BitwiseOp
}

func (e *Bitwise) marshal(fam byte) ([]byte, error) {
	data, err := e.marshalData(fam)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("bitwise\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Bitwise) marshalData(fam byte) ([]byte, error) {
	mask, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_DATA_VALUE, Data: e.Mask},
	})
	if err != nil {
		return nil, err
	}
	xor, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_DATA_VALUE, Data: e.Xor},
	})
	if err != nil {
		return nil, err
	}
	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_DATA_VALUE, Data: e.Data},
	})
	if err != nil {
		return nil, err
	}

	attrs := []netlink.Attribute{
		{Type: unix.NFTA_BITWISE_SREG, Data: binaryutil.BigEndian.PutUint32(e.SourceRegister)},
		{Type: unix.NFTA_BITWISE_DREG, Data: binaryutil.BigEndian.PutUint32(e.DestRegister)},
		{Type: unix.NFTA_BITWISE_LEN, Data: binaryutil.BigEndian.PutUint32(e.Len)},
	}

	maskAttr := netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_BITWISE_MASK, Data: mask}
	xorAttr := netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_BITWISE_XOR, Data: xor}
	opAttr := netlink.Attribute{Type: NFTA_BITWISE_OP, Data: binaryutil.BigEndian.PutUint32(uint32(e.Op))}
	dataAttr := netlink.Attribute{Type: unix.NLA_F_NESTED | NFTA_BITWISE_DATA, Data: data}
	sreg2Attr := netlink.Attribute{Type: NFTA_BITWISE_SREG2, Data: binaryutil.BigEndian.PutUint32(e.SourceRegister2)}

	switch e.Op {
	case BitwiseOpMaskXor:
		attrs = append(attrs, maskAttr, xorAttr)
	case BitwiseOpLshift, BitwiseOpRshift:
		attrs = append(attrs, opAttr, dataAttr)
	case BitwiseOpAnd, BitwiseOpOr, BitwiseOpXor:
		attrs = append(attrs, opAttr)
		if e.SourceRegister2 != 0 {
			// operand taken from a second register
			attrs = append(attrs, sreg2Attr)
		} else {
			// operand taken from an immediate value
			attrs = append(attrs, dataAttr)
		}
	}

	return netlink.MarshalAttributes(attrs)
}

func (e *Bitwise) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_BITWISE_SREG:
			e.SourceRegister = ad.Uint32()
		case unix.NFTA_BITWISE_DREG:
			e.DestRegister = ad.Uint32()
		case unix.NFTA_BITWISE_LEN:
			e.Len = ad.Uint32()
		case unix.NFTA_BITWISE_MASK:
			// Since NFTA_BITWISE_MASK is nested, it requires additional decoding
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					switch nad.Type() {
					case unix.NFTA_DATA_VALUE:
						e.Mask = nad.Bytes()
					}
				}
				return nil
			})
		case unix.NFTA_BITWISE_XOR:
			// Since NFTA_BITWISE_XOR is nested, it requires additional decoding
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					switch nad.Type() {
					case unix.NFTA_DATA_VALUE:
						e.Xor = nad.Bytes()
					}
				}
				return nil
			})
		case NFTA_BITWISE_OP:
			e.Op = BitwiseOp(ad.Uint32())
		case NFTA_BITWISE_DATA:
			// Since NFTA_BITWISE_DATA is nested, it requires additional decoding
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					switch nad.Type() {
					case unix.NFTA_DATA_VALUE:
						e.Data = nad.Bytes()
					}
				}
				return nil
			})
		case NFTA_BITWISE_SREG2:
			e.SourceRegister2 = ad.Uint32()
		}
	}
	return ad.Err()
}
