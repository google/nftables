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

type PayloadBase uint32

// Possible PayloadBase values.
const (
	PayloadBaseLLHeader        PayloadBase = unix.NFT_PAYLOAD_LL_HEADER
	PayloadBaseNetworkHeader   PayloadBase = unix.NFT_PAYLOAD_NETWORK_HEADER
	PayloadBaseTransportHeader PayloadBase = unix.NFT_PAYLOAD_TRANSPORT_HEADER
)

type Payload struct {
	DestRegister uint32
	Base         PayloadBase
	Offset       uint32
	Len          uint32
}

func (e *Payload) marshal() ([]byte, error) {
	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_PAYLOAD_DREG, Data: binaryutil.BigEndian.PutUint32(e.DestRegister)},
		{Type: unix.NFTA_PAYLOAD_BASE, Data: binaryutil.BigEndian.PutUint32(uint32(e.Base))},
		{Type: unix.NFTA_PAYLOAD_OFFSET, Data: binaryutil.BigEndian.PutUint32(e.Offset)},
		{Type: unix.NFTA_PAYLOAD_LEN, Data: binaryutil.BigEndian.PutUint32(e.Len)},
	})
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("payload\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Payload) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_PAYLOAD_DREG:
			e.DestRegister = ad.Uint32()
		case unix.NFTA_PAYLOAD_BASE:
			e.Base = PayloadBase(ad.Uint32())
		case unix.NFTA_PAYLOAD_OFFSET:
			e.Offset = ad.Uint32()
		case unix.NFTA_PAYLOAD_LEN:
			e.Len = ad.Uint32()
		}
	}
	return ad.Err()
}
