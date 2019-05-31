// Copyright 2019 Google LLC. All Rights Reserved.
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

// Range implements range expression
type Range struct {
	Op       CmpOp
	Register uint32
	FromData uint32
	ToData   uint32
}

func (e *Range) marshal() ([]byte, error) {
	var attrs []netlink.Attribute
	if e.Register > 0 {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RANGE_SREG, Data: binaryutil.BigEndian.PutUint32(e.Register)})
	}
	attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RANGE_OP, Data: binaryutil.BigEndian.PutUint32(uint32(e.Op))})
	if e.FromData > 0 {
		attrs = append(attrs, netlink.Attribute{Length: 12, Type: unix.NLA_F_NESTED | unix.NFTA_RANGE_FROM_DATA, Data: []byte{}})
		attrs = append(attrs, netlink.Attribute{Length: 6, Type: unix.NFTA_DATA_VALUE, Data: binaryutil.BigEndian.PutUint32(e.FromData)})
	}
	if e.ToData > 0 {
		attrs = append(attrs, netlink.Attribute{Length: 12, Type: unix.NLA_F_NESTED | unix.NFTA_RANGE_TO_DATA, Data: []byte{}})
		attrs = append(attrs, netlink.Attribute{Length: 6, Type: unix.NFTA_DATA_VALUE, Data: binaryutil.BigEndian.PutUint32(e.ToData)})
	}
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("range\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Range) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RANGE_OP:
			e.Op = CmpOp(ad.Uint32())
		case unix.NFTA_RANGE_SREG:
			e.Register = ad.Uint32()
		case unix.NFTA_RANGE_FROM_DATA:
			e.FromData = ad.Uint32()
		case unix.NFTA_RANGE_TO_DATA:
			e.ToData = ad.Uint32()
		}
	}
	return ad.Err()
}
