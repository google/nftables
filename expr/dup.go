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

type Dup struct {
	RegAddr uint32
	RegDev  uint32
}

func (d *Dup) marshal() ([]byte, error) {
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_DUP_SREG_ADDR, Data: binaryutil.BigEndian.PutUint32(d.RegAddr)},
	}

	if d.RegDev != 0 {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_DUP_SREG_DEV, Data: binaryutil.BigEndian.PutUint32(d.RegDev)})
	}

	data, err := netlink.MarshalAttributes(attrs)

	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("dup\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (d *Dup) unmarshal(data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_DUP_SREG_ADDR:
			d.RegAddr = ad.Uint32()
		case unix.NFTA_DUP_SREG_DEV:
			d.RegDev = ad.Uint32()
		}
	}
	return ad.Err()
}
