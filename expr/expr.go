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

// Package expr provides nftables rule expressions.
package expr

import (
	"fmt"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Marshal serializes the specified expression into a byte slice.
func Marshal(e Any) ([]byte, error) {
	return e.marshal()
}

// Unmarshal fills an expression from the specified byte slice.
func Unmarshal(data []byte, e Any) error {
	return e.unmarshal(data)
}

// Any is an interface implemented by any expression type.
type Any interface {
	marshal() ([]byte, error)
	unmarshal([]byte) error
}

// MetaKey specifies which piece of meta information should be loaded. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
type MetaKey uint32

// Possible MetaKey values.
const (
	MetaKeyLEN        MetaKey = unix.NFT_META_LEN
	MetaKeyPROTOCOL   MetaKey = unix.NFT_META_PROTOCOL
	MetaKeyPRIORITY   MetaKey = unix.NFT_META_PRIORITY
	MetaKeyMARK       MetaKey = unix.NFT_META_MARK
	MetaKeyIIF        MetaKey = unix.NFT_META_IIF
	MetaKeyOIF        MetaKey = unix.NFT_META_OIF
	MetaKeyIIFNAME    MetaKey = unix.NFT_META_IIFNAME
	MetaKeyOIFNAME    MetaKey = unix.NFT_META_OIFNAME
	MetaKeyIIFTYPE    MetaKey = unix.NFT_META_IIFTYPE
	MetaKeyOIFTYPE    MetaKey = unix.NFT_META_OIFTYPE
	MetaKeySKUID      MetaKey = unix.NFT_META_SKUID
	MetaKeySKGID      MetaKey = unix.NFT_META_SKGID
	MetaKeyNFTRACE    MetaKey = unix.NFT_META_NFTRACE
	MetaKeyRTCLASSID  MetaKey = unix.NFT_META_RTCLASSID
	MetaKeySECMARK    MetaKey = unix.NFT_META_SECMARK
	MetaKeyNFPROTO    MetaKey = unix.NFT_META_NFPROTO
	MetaKeyL4PROTO    MetaKey = unix.NFT_META_L4PROTO
	MetaKeyBRIIIFNAME MetaKey = unix.NFT_META_BRI_IIFNAME
	MetaKeyBRIOIFNAME MetaKey = unix.NFT_META_BRI_OIFNAME
	MetaKeyPKTTYPE    MetaKey = unix.NFT_META_PKTTYPE
	MetaKeyCPU        MetaKey = unix.NFT_META_CPU
	MetaKeyIIFGROUP   MetaKey = unix.NFT_META_IIFGROUP
	MetaKeyOIFGROUP   MetaKey = unix.NFT_META_OIFGROUP
	MetaKeyCGROUP     MetaKey = unix.NFT_META_CGROUP
	MetaKeyPRANDOM    MetaKey = unix.NFT_META_PRANDOM
)

// Meta loads packet meta information for later comparisons. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
type Meta struct {
	Key      MetaKey
	Register uint32
}

func (e *Meta) marshal() ([]byte, error) {
	exprData, err := netlink.MarshalAttributes(
		[]netlink.Attribute{
			{Type: unix.NFTA_META_KEY, Data: binaryutil.BigEndian.PutUint32(uint32(e.Key))},
			{Type: unix.NFTA_META_DREG, Data: binaryutil.BigEndian.PutUint32(e.Register)},
		},
	)
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("meta\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (e *Meta) unmarshal(data []byte) error {
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attrs {
		switch attr.Type {
		case unix.NFTA_META_DREG:
			e.Register = binaryutil.BigEndian.Uint32(attr.Data)
		case unix.NFTA_META_KEY:
			e.Key = MetaKey(binaryutil.BigEndian.Uint32(attr.Data))
		}
	}

	return nil
}

// Masq (Masquerade) is a special case of SNAT, where the source address is
// automagically set to the address of the output interface. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)#Masquerading
type Masq struct{}

func (e *Masq) marshal() ([]byte, error) {
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("masq\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: nil},
	})
}

func (e *Masq) unmarshal(data []byte) error {
	return fmt.Errorf("not yet implemented")
}

// CmpOp specifies which type of comparison should be performed.
type CmpOp uint32

// Possible CmpOp values.
const (
	CmpOpEq  CmpOp = unix.NFT_CMP_EQ
	CmpOpNeq CmpOp = unix.NFT_CMP_NEQ
	CmpOpLt  CmpOp = unix.NFT_CMP_LT
	CmpOpLte CmpOp = unix.NFT_CMP_LTE
	CmpOpGt  CmpOp = unix.NFT_CMP_GT
	CmpOpGte CmpOp = unix.NFT_CMP_GTE
)

// Cmp compares a register with the specified data.
type Cmp struct {
	Op       CmpOp
	Register uint32
	Data     []byte
}

func (e *Cmp) marshal() ([]byte, error) {
	cmpData, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_DATA_VALUE, Data: e.Data},
	})
	if err != nil {
		return nil, err
	}
	exprData, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_CMP_SREG, Data: binaryutil.BigEndian.PutUint32(e.Register)},
		{Type: unix.NFTA_CMP_OP, Data: binaryutil.BigEndian.PutUint32(uint32(e.Op))},
		{Type: unix.NLA_F_NESTED | unix.NFTA_CMP_DATA, Data: cmpData},
	})
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("cmp\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: exprData},
	})
}

func (e *Cmp) unmarshal(data []byte) error {
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		return err
	}
	for _, attr := range attrs {
		switch attr.Type {
		case unix.NFTA_CMP_SREG:
			e.Register = binaryutil.BigEndian.Uint32(attr.Data)
		case unix.NFTA_CMP_OP:
			e.Op = CmpOp(binaryutil.BigEndian.Uint32(attr.Data))
		case unix.NFTA_CMP_DATA:
			attrs, err := netlink.UnmarshalAttributes(attr.Data)
			if err != nil {
				return err
			}
			if len(attrs) == 1 && attrs[0].Type == unix.NFTA_DATA_VALUE {
				e.Data = attrs[0].Data
			}
		}
	}

	return nil
}
