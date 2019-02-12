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
	"fmt"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Lookup represents a match against the contents of a set.
type Lookup struct {
	SourceRegister uint32
	DestRegister   uint32

	SetID   uint32
	SetName string
	Invert  bool
}

func (e *Lookup) marshal() ([]byte, error) {
	// See: https://git.netfilter.org/libnftnl/tree/src/expr/lookup.c?id=6dc1c3d8bb64077da7f3f28c7368fb087d10a492#n115
	var opAttrs []netlink.Attribute
	if e.SourceRegister != 0 {
		opAttrs = append(opAttrs, netlink.Attribute{Type: unix.NFTA_LOOKUP_SREG, Data: binaryutil.BigEndian.PutUint32(e.SourceRegister)})
	}
	if e.DestRegister != 0 {
		opAttrs = append(opAttrs, netlink.Attribute{Type: unix.NFTA_LOOKUP_DREG, Data: binaryutil.BigEndian.PutUint32(e.DestRegister)})
	}
	if e.Invert {
		opAttrs = append(opAttrs, netlink.Attribute{Type: unix.NFTA_LOOKUP_FLAGS, Data: binaryutil.BigEndian.PutUint32(unix.NFT_LOOKUP_F_INV)})
	}
	opAttrs = append(opAttrs,
		netlink.Attribute{Type: unix.NFTA_LOOKUP_SET, Data: []byte(e.SetName + "\x00")},
		netlink.Attribute{Type: unix.NFTA_LOOKUP_SET_ID, Data: binaryutil.BigEndian.PutUint32(e.SetID)},
	)
	opData, err := netlink.MarshalAttributes(opAttrs)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("lookup\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: opData},
	})
}

func (e *Lookup) unmarshal(data []byte) error {
	return fmt.Errorf("not yet implemented")
}
