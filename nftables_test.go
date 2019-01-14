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

package nftables_test

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nfdump returns a hexdump of 4 bytes per line (like nft --debug=all), allowing
// users to make sense of large byte literals more easily.
func nfdump(b []byte) string {
	var buf bytes.Buffer
	i := 0
	for ; i < len(b); i += 4 {
		// TODO: show printable characters as ASCII
		fmt.Fprintf(&buf, "%02x %02x %02x %02x\n",
			b[i],
			b[i+1],
			b[i+2],
			b[i+3])
	}
	for ; i < len(b); i++ {
		fmt.Fprintf(&buf, "%02x ", b[i])
	}
	return buf.String()
}

// linediff returns a side-by-side diff of two nfdump() return values, flagging
// lines which are not equal with an exclamation point prefix.
func linediff(a, b string) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "got -- want\n")
	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")
	for idx, lineA := range linesA {
		if idx >= len(linesB) {
			break
		}
		lineB := linesB[idx]
		prefix := "! "
		if lineA == lineB {
			prefix = "  "
		}
		fmt.Fprintf(&buf, "%s%s -- %s\n", prefix, lineA, lineB)
	}
	return buf.String()
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func TestConfigureNAT(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add table ip nat
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip nat
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain nat prerouting '{' type nat hook prerouting priority 0 \; '}'
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x03\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x08\x00\x07\x00\x6e\x61\x74\x00"),
		// nft add chain nat postrouting '{' type nat hook postrouting priority 100 \; '}'
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x10\x00\x03\x00\x70\x6f\x73\x74\x72\x6f\x75\x74\x69\x6e\x67\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x04\x08\x00\x02\x00\x00\x00\x00\x64\x08\x00\x07\x00\x6e\x61\x74\x00"),
		// nft add rule nat postrouting oifname uplink0 masquerade
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x10\x00\x02\x00\x70\x6f\x73\x74\x72\x6f\x75\x74\x69\x6e\x67\x00\x74\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x07\x08\x00\x01\x00\x00\x00\x00\x01\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x75\x70\x6c\x69\x6e\x6b\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x04\x00\x02\x80"),
		// nft add rule nat prerouting iif uplink0 tcp dport 4070 dnat 192.168.23.2:4080
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x98\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x75\x70\x6c\x69\x6e\x6b\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x0f\xe6\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\xc0\xa8\x17\x02\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x06\x00\x01\x00\x0f\xf0\x00\x00\x30\x00\x01\x80\x08\x00\x01\x00\x6e\x61\x74\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x05\x00\x00\x00\x00\x02"),
		// nft add rule nat prerouting iifname uplink0 udp dport 4070-4090 dnat 192.168.23.2:4070-4090
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\xf8\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x75\x70\x6c\x69\x6e\x6b\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x11\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x05\x0c\x00\x03\x80\x06\x00\x01\x00\x0f\xe6\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x03\x0c\x00\x03\x80\x06\x00\x01\x00\x0f\xfa\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\xc0\xa8\x17\x02\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x06\x00\x01\x00\x0f\xe6\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x03\x0c\x00\x02\x80\x06\x00\x01\x00\x0f\xfa\x00\x00\x38\x00\x01\x80\x08\x00\x01\x00\x6e\x61\x74\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x05\x00\x00\x00\x00\x02\x08\x00\x06\x00\x00\x00\x00\x03"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %x", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
				}
				want = want[1:]
			}
			return req, nil
		},
	}

	c.FlushRuleset()

	nat := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
	})

	postrouting := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
	})

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: postrouting,
		Exprs: []expr.Any{
			// meta load oifname => reg 1
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			// cmp eq reg 1 0x696c7075 0x00306b6e 0x00000000 0x00000000
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname("uplink0"),
			},
			// masq
			&expr.Masq{},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			// [ cmp eq reg 1 0x696c7075 0x00306b6e 0x00000000 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname("uplink0"),
			},

			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // TODO
				Len:          2, // TODO
			},
			// [ cmp eq reg 1 0x0000e60f ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(4070),
			},

			// [ immediate reg 1 0x0217a8c0 ]
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("192.168.23.2").To4(),
			},
			// [ immediate reg 2 0x0000f00f ]
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(4080),
			},
			// [ nat dnat ip addr_min reg 1 addr_max reg 0 proto_min reg 2 proto_max reg 0 ]
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: []expr.Any{
			// [ meta load iifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			// [ cmp eq reg 1 0x696c7075 0x00306b6e 0x00000000 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname("uplink0"),
			},

			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // TODO
				Len:          2, // TODO
			},
			// [ cmp gte reg 1 0x0000e60f ]
			&expr.Cmp{
				Op:       expr.CmpOpGte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(4070),
			},
			// [ cmp lte reg 1 0x0000fa0f ]
			&expr.Cmp{
				Op:       expr.CmpOpLte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(4090),
			},

			// [ immediate reg 1 0x0217a8c0 ]
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("192.168.23.2").To4(),
			},
			// [ immediate reg 2 0x0000f00f ]
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint16(4070),
			},
			// [ immediate reg 3 0x0000fa0f ]
			&expr.Immediate{
				Register: 3,
				Data:     binaryutil.BigEndian.PutUint16(4090),
			},
			// [ nat dnat ip addr_min reg 1 addr_max reg 0 proto_min reg 2 proto_max reg 3 ]
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
				RegProtoMax: 3,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureNATSourceAddress(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add table ip nat
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip nat
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain nat postrouting '{' type nat hook postrouting priority 100 \; '}'
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x10\x00\x03\x00\x70\x6f\x73\x74\x72\x6f\x75\x74\x69\x6e\x67\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x04\x08\x00\x02\x00\x00\x00\x00\x64\x08\x00\x07\x00\x6e\x61\x74\x00"),
		// nft add rule nat postrouting ip saddr 192.168.69.2 masquerade
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x10\x00\x02\x00\x70\x6f\x73\x74\x72\x6f\x75\x74\x69\x6e\x67\x00\x78\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\xc0\xa8\x45\x02\x14\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x04\x00\x02\x80"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %x", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
				}
				want = want[1:]
			}
			return req, nil
		},
	}

	c.FlushRuleset()

	nat := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	postrouting := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
	})

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: postrouting,
		Exprs: []expr.Any{
			// payload load 4b @ network header + 12 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			// cmp eq reg 1 0x0245a8c0
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     net.ParseIP("192.168.69.2").To4(),
			},

			// masq
			&expr.Masq{},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestGetRule(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft list chain ip filter forward

	want := [][]byte{
		[]byte{0x2, 0x0, 0x0, 0x0, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xa, 0x0, 0x2, 0x0, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x0, 0x0, 0x0},
	}

	// The reply messages come from adding log.Printf("msgs: %#v", msgs) to
	// (*github.com/mdlayher/netlink/Conn).receive
	reply := [][]netlink.Message{
		nil,
		[]netlink.Message{netlink.Message{Header: netlink.Header{Length: 0x68, Type: 0xa06, Flags: 0x802, Sequence: 0x9acb0443, PID: 0xba38ef3c}, Data: []uint8{0x2, 0x0, 0x0, 0xc, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x0, 0xc, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x30, 0x0, 0x4, 0x0, 0x2c, 0x0, 0x1, 0x0, 0xc, 0x0, 0x1, 0x0, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x0, 0x1c, 0x0, 0x2, 0x0, 0xc, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6d, 0x92, 0x20, 0x20, 0xc, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x48, 0xd9}}},
		[]netlink.Message{netlink.Message{Header: netlink.Header{Length: 0x14, Type: 0x3, Flags: 0x2, Sequence: 0x9acb0443, PID: 0xba38ef3c}, Data: []uint8{0x0, 0x0, 0x0, 0x0}}},
	}

	c := &nftables.Conn{
		TestDial: func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %x", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
				}
				want = want[1:]
			}
			rep := reply[0]
			reply = reply[1:]
			return rep, nil
		},
	}

	rules, err := c.GetRule(
		&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		},
		&nftables.Chain{
			Name: "input",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}

	rule := rules[0]
	if got, want := len(rule.Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	ce, ok := rule.Exprs[0].(*expr.Counter)
	if !ok {
		t.Fatalf("unexpected expression type: got %T, want *expr.Counter", rule.Exprs[0])
	}

	if got, want := ce.Packets, uint64(674009); got != want {
		t.Errorf("unexpected number of packets: got %d, want %d", got, want)
	}

	if got, want := ce.Bytes, uint64(1838293024); got != want {
		t.Errorf("unexpected number of bytes: got %d, want %d", got, want)
	}
}

func TestAddCounter(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add table ip nat
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add counter ip filter fwded
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0a\x00\x02\x00\x66\x77\x64\x65\x64\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x01\x1c\x00\x04\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		// nft add rule ip filter forward counter name fwded
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x2c\x00\x04\x80\x28\x00\x01\x80\x0b\x00\x01\x00\x6f\x62\x6a\x72\x65\x66\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x09\x00\x02\x00\x66\x77\x64\x65\x64\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %x", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
				}
				want = want[1:]
			}
			return req, nil
		},
	}

	c.AddObj(&nftables.CounterObj{
		Table:   &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Name:    "fwded",
		Bytes:   0,
		Packets: 0,
	})

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{Name: "forward", Type: nftables.ChainTypeFilter},
		Exprs: []expr.Any{
			&expr.Objref{
				Type: 1,
				Name: "fwded",
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestGetObjReset(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft list chain ip filter forward

	want := [][]byte{
		[]byte{0x2, 0x0, 0x0, 0x0, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xa, 0x0, 0x2, 0x0, 0x66, 0x77, 0x64, 0x65, 0x64, 0x0, 0x0, 0x0, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x1},
	}

	// The reply messages come from adding log.Printf("msgs: %#v", msgs) to
	// (*github.com/mdlayher/netlink/Conn).receive
	reply := [][]netlink.Message{
		nil,
		[]netlink.Message{netlink.Message{Header: netlink.Header{Length: 0x64, Type: 0xa12, Flags: 0x802, Sequence: 0x9acb0443, PID: 0xde9}, Data: []uint8{0x2, 0x0, 0x0, 0x10, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xa, 0x0, 0x2, 0x0, 0x66, 0x77, 0x64, 0x65, 0x64, 0x0, 0x0, 0x0, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1c, 0x0, 0x4, 0x0, 0xc, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x61, 0xc, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0xc, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}}},
		[]netlink.Message{netlink.Message{Header: netlink.Header{Length: 0x14, Type: 0x3, Flags: 0x2, Sequence: 0x9acb0443, PID: 0xde9}, Data: []uint8{0x0, 0x0, 0x0, 0x0}}},
	}

	c := &nftables.Conn{
		TestDial: func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %x", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
				}
				want = want[1:]
			}
			rep := reply[0]
			reply = reply[1:]
			return rep, nil
		},
	}

	filter := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	objs, err := c.GetObjReset(&nftables.CounterObj{
		Table: filter,
		Name:  "fwded",
	})

	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(objs), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}

	obj := objs[0]
	co, ok := obj.(*nftables.CounterObj)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *nftables.CounterObj", obj)
	}
	if got, want := co.Table.Name, filter.Name; got != want {
		t.Errorf("unexpected table name: got %q, want %q", got, want)
	}
	if got, want := co.Table.Family, filter.Family; got != want {
		t.Errorf("unexpected table family: got %d, want %d", got, want)
	}
	if got, want := co.Packets, uint64(9); got != want {
		t.Errorf("unexpected number of packets: got %d, want %d", got, want)
	}
	if got, want := co.Bytes, uint64(1121); got != want {
		t.Errorf("unexpected number of bytes: got %d, want %d", got, want)
	}
}

func TestConfigureClamping(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add table ip nat
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Mangle_TCP_options
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain filter forward '{' type filter hook forward priority 0 \; '}'
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip filter forward oifname uplink0 tcp flags syn tcp option maxseg size set rt mtu
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xf0\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x07\x08\x00\x01\x00\x00\x00\x00\x01\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x75\x70\x6c\x69\x6e\x6b\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x0d\x08\x00\x04\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x0c\x00\x04\x80\x05\x00\x01\x00\x02\x00\x00\x00\x0c\x00\x05\x80\x05\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x05\x00\x01\x00\x00\x00\x00\x00\x20\x00\x01\x80\x07\x00\x01\x00\x72\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x01\x00\x00\x00\x00\x01\x40\x00\x01\x80\x0e\x00\x01\x00\x62\x79\x74\x65\x6f\x72\x64\x65\x72\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x04\x00\x00\x00\x00\x02\x08\x00\x05\x00\x00\x00\x00\x02\x3c\x00\x01\x80\x0b\x00\x01\x00\x65\x78\x74\x68\x64\x72\x00\x00\x2c\x00\x02\x80\x08\x00\x07\x00\x00\x00\x00\x01\x05\x00\x02\x00\x02\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x08\x00\x06\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %x", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
				}
				want = want[1:]
			}
			return req, nil
		},
	}

	c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	forward := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ meta load oifname => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			// [ cmp eq reg 1 0x30707070 0x00000000 0x00000000 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname("uplink0"),
			},

			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 1b @ transport header + 13 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       13, // TODO
				Len:          1,  // TODO
			},
			// [ bitwise reg 1 = (reg=1 & 0x00000002 ) ^ 0x00000000 ]
			&expr.Bitwise{
				DestRegister:   1,
				SourceRegister: 1,
				Len:            1,
				Mask:           []byte{0x02},
				Xor:            []byte{0x00},
			},
			// [ cmp neq reg 1 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00},
			},

			// [ rt load tcpmss => reg 1 ]
			&expr.Rt{
				Register: 1,
				Key:      expr.RtTCPMSS,
			},
			// [ byteorder reg 1 = hton(reg 1, 2, 2) ]
			&expr.Byteorder{
				DestRegister:   1,
				SourceRegister: 1,
				Op:             expr.ByteorderHton,
				Len:            2,
				Size:           2,
			},
			// [ exthdr write tcpopt reg 1 => 2b @ 2 + 2 ]
			&expr.Exthdr{
				SourceRegister: 1,
				Type:           2, // TODO
				Offset:         2,
				Len:            2,
				Op:             expr.ExthdrOpTcpopt,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestDropVerdict(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add table ip nat
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Mangle_TCP_options
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain filter forward '{' type filter hook forward priority 0 \; '}'
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule filter forward tcp dport 1234 drop
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xe4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x04\xd2\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: func(req []netlink.Message) ([]netlink.Message, error) {
			for idx, msg := range req {
				b, err := msg.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if len(b) < 16 {
					continue
				}
				b = b[16:]
				if len(want) == 0 {
					t.Errorf("no want entry for message %d: %x", idx, b)
					continue
				}
				if got, want := b, want[0]; !bytes.Equal(got, want) {
					t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
				}
				want = want[1:]
			}
			return req, nil
		},
	}

	c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	forward := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ cmp eq reg 1 0x0000d204 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x04, 0xd2},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
