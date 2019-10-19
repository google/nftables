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
	"flag"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var (
	enableSysTests = flag.Bool("run_system_tests", false, "Run tests that operate against the live kernel")
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

// openSystemNFTConn returns a netlink connection that tests against
// the running kernel in a separate network namespace.
// cleanupSystemNFTConn() must be called from a defer to cleanup
// created network namespace.
func openSystemNFTConn(t *testing.T) (*nftables.Conn, netns.NsHandle) {
	t.Helper()
	if !*enableSysTests {
		t.SkipNow()
	}
	// We lock the goroutine into the current thread, as namespace operations
	// such as those invoked by `netns.New()` are thread-local. This is undone
	// in cleanupSystemNFTConn().
	runtime.LockOSThread()

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New() failed: %v", err)
	}
	return &nftables.Conn{NetNS: int(ns)}, ns
}

func cleanupSystemNFTConn(t *testing.T, newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
	}
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

func TestDelRule(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft delete rule ipv4table ipv4chain-1 handle 9
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x31\x00\x0c\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x09"),
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

	c.DelRule(&nftables.Rule{
		Table:  &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain:  &nftables.Chain{Name: "ipv4chain-1", Type: nftables.ChainTypeFilter},
		Handle: uint64(9),
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestLog(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		//  nft add rule ipv4table ipv4chain-1  log prefix nftables
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x31\x00\x24\x00\x04\x80\x20\x00\x01\x80\x08\x00\x01\x00\x6c\x6f\x67\x00\x14\x00\x02\x80\x0d\x00\x02\x00\x6e\x66\x74\x61\x62\x6c\x65\x73\x00\x00\x00\x00"),
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

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{Name: "ipv4chain-1", Type: nftables.ChainTypeFilter},
		Exprs: []expr.Any{
			&expr.Log{
				Key:  unix.NFTA_LOG_PREFIX,
				Data: []byte("nftables"),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestTProxy(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add rule filter divert ip protocol tcp tproxy to :50080
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0b\x00\x02\x00\x64\x69\x76\x65\x72\x74\x00\x00\xb4\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x06\x00\x01\x00\xc3\xa0\x00\x00\x24\x00\x01\x80\x0b\x00\x01\x00\x74\x70\x72\x6f\x78\x79\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x01"),
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

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name:     "divert",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: -150,
		},
		Exprs: []expr.Any{
			//	[ payload load 1b @ network header + 9 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			//	[ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			//	[ immediate reg 1 0x0000a0c3 ]
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(50080)},
			//	[ tproxy ip port reg 1 ]
			&expr.TProxy{
				Family:      byte(nftables.TableFamilyIPv4),
				TableFamily: byte(nftables.TableFamilyIPv4),
				RegPort:     1,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestCt(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// sudo nft add rule ipv4table ipv4chain-5 ct mark 123 counter
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x35\x00\x24\x00\x04\x80\x20\x00\x01\x80\x07\x00\x01\x00\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x01\x00\x00\x00\x00\x01"),
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

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name: "ipv4chain-5",
		},
		Exprs: []expr.Any{
			//	[ ct load mark => reg 1 ]
			&expr.Ct{
				Key:      unix.NFT_CT_MARK,
				Register: 1,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestCtSet(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// sudo nft add rule filter forward ct mark set 1
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x50\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x01\x00\x00\x00\x20\x00\x01\x80\x07\x00\x01\x00\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x04\x00\x00\x00\x00\x01"),
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

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name: "forward",
		},
		Exprs: []expr.Any{
			//	[ immediate reg 1 0x00000001 ]
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(1),
			},
			// [ ct set mark with reg 1 ]
			&expr.Ct{
				Key:            expr.CtKeyMARK,
				Register:       1,
				SourceRegister: true,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestAddRuleWithPosition(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add rule ip ipv4table ipv4chain-1 position 2 ip version 6
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x31\x00\xa8\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x0c\x00\x04\x80\x05\x00\x01\x00\xf0\x00\x00\x00\x0c\x00\x05\x80\x05\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x60\x00\x00\x00\x0c\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x02"),
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

	c.AddRule(&nftables.Rule{
		Position: 2,
		Table:    &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name:     "ipv4chain-1",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: 0,
		},

		Exprs: []expr.Any{
			// [ payload load 1b @ network header + 0 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       0, // Offset for a transport protocol header
				Len:          1, // 1 bytes for port
			},
			// [ bitwise reg 1 = (reg=1 & 0x000000f0 ) ^ 0x00000000 ]
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            1,
				Mask:           []byte{0xf0},
				Xor:            []byte{0x0},
			},
			// [ cmp eq reg 1 0x00000060 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{(0x6 << 4)},
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestAddChain(t *testing.T) {
	tests := []struct {
		name  string
		chain *nftables.Chain
		want  [][]byte
	}{
		{
			name: "Base chain",
			chain: &nftables.Chain{
				Name:     "base-chain",
				Hooknum:  nftables.ChainHookPrerouting,
				Priority: 0,
				Type:     nftables.ChainTypeFilter,
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain { type filter hook prerouting priority 0 \; }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
		},
		{
			name: "Regular chain",
			chain: &nftables.Chain{
				Name: "regular-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter regular-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x12\x00\x03\x00\x72\x65\x67\x75\x6c\x61\x72\x2d\x63\x68\x61\x69\x6e\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
		},
	}

	for _, tt := range tests {
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
					if len(tt.want[idx]) == 0 {
						t.Errorf("no want entry for message %d: %x", idx, b)
						continue
					}
					got := b
					if !bytes.Equal(got, tt.want[idx]) {
						t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(tt.want[idx])))
					}
				}
				return req, nil
			},
		}

		filter := c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		})

		tt.chain.Table = filter
		c.AddChain(tt.chain)
		if err := c.Flush(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDelChain(t *testing.T) {
	tests := []struct {
		name  string
		chain *nftables.Chain
		want  [][]byte
	}{
		{
			name: "Base chain",
			chain: &nftables.Chain{
				Name:     "base-chain",
				Hooknum:  nftables.ChainHookPrerouting,
				Priority: 0,
				Type:     nftables.ChainTypeFilter,
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft delete chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
		},
		{
			name: "Regular chain",
			chain: &nftables.Chain{
				Name: "regular-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft delete chain ip filter regular-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x12\x00\x03\x00\x72\x65\x67\x75\x6c\x61\x72\x2d\x63\x68\x61\x69\x6e\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
		},
	}

	for _, tt := range tests {
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
					if len(tt.want[idx]) == 0 {
						t.Errorf("no want entry for message %d: %x", idx, b)
						continue
					}
					got := b
					if !bytes.Equal(got, tt.want[idx]) {
						t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(tt.want[idx])))
					}
				}
				return req, nil
			},
		}

		tt.chain.Table = &nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		}
		c.DelChain(tt.chain)
		if err := c.Flush(); err != nil {
			t.Fatal(err)
		}
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

func TestCreateUseAnonymousSet(t *testing.T) {
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
		// Create anonymous set with key len of 2 bytes and data len of 0 bytes
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x5f\x5f\x73\x65\x74\x25\x64\x00\x08\x00\x03\x00\x00\x00\x00\x03\x08\x00\x04\x00\x00\x00\x00\x0d\x08\x00\x05\x00\x00\x00\x00\x02\x08\x00\x0a\x00\x00\x00\x00\x01\x0c\x00\x09\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0a\x00\x0d\x00\x00\x04\x02\x00\x00\x00\x00\x00"),
		// Assign the two values to the aforementioned anonymous set
		[]byte("\x02\x00\x00\x00\x0c\x00\x02\x00\x5f\x5f\x73\x65\x74\x25\x64\x00\x08\x00\x04\x00\x00\x00\x00\x01\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x24\x00\x03\x80\x10\x00\x01\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x00\x45\x00\x00\x10\x00\x02\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x04\x8b\x00\x00"),
		// nft add rule filter forward tcp dport {69, 1163} drop
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xe8\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x30\x00\x01\x80\x0b\x00\x01\x00\x6c\x6f\x6f\x6b\x75\x70\x00\x00\x20\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x01\x00\x5f\x5f\x73\x65\x74\x25\x64\x00\x08\x00\x04\x00\x00\x00\x00\x01\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00"),
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

	set := &nftables.Set{
		Anonymous: true,
		Constant:  true,
		Table:     filter,
		KeyType:   nftables.TypeInetService,
	}

	if err := c.AddSet(set, []nftables.SetElement{
		{Key: binaryutil.BigEndian.PutUint16(69)},
		{Key: binaryutil.BigEndian.PutUint16(1163)},
	}); err != nil {
		t.Errorf("c.AddSet() failed: %v", err)
	}

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: &nftables.Chain{Name: "forward", Type: nftables.ChainTypeFilter},
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
			// [ lookup reg 1 set __set%d ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        set.Name,
				SetID:          set.ID,
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

func TestCreateUseNamedSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.SetAddElements(portSet, []nftables.SetElement{{Key: binaryutil.BigEndian.PutUint16(22)}}); err != nil {
		t.Errorf("c.SetVal(portSet) failed: %v", err)
	}

	ipSet := &nftables.Set{
		Table:   filter,
		Name:    "IPs_4_dayz",
		KeyType: nftables.TypeIPAddr,
	}
	if err := c.AddSet(ipSet, []nftables.SetElement{{Key: []byte(net.ParseIP("192.168.1.64").To4())}}); err != nil {
		t.Errorf("c.AddSet(ipSet) failed: %v", err)
	}
	if err := c.SetAddElements(ipSet, []nftables.SetElement{{Key: []byte(net.ParseIP("192.168.1.42").To4())}}); err != nil {
		t.Errorf("c.SetVal(ipSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	sets, err := c.GetSets(filter)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(sets) != 2 {
		t.Fatalf("len(sets) = %d, want 2", len(sets))
	}
	if sets[0].Name != "kek" {
		t.Errorf("set[0].Name = %q, want kek", sets[0].Name)
	}
	if sets[1].Name != "IPs_4_dayz" {
		t.Errorf("set[1].Name = %q, want IPs_4_dayz", sets[1].Name)
	}
}

func TestCreateDeleteNamedSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	c.DelSet(portSet)

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	sets, err := c.GetSets(filter)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(sets) != 0 {
		t.Fatalf("len(sets) = %d, want 0", len(sets))
	}
}

func TestDeleteElementNamedSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, []nftables.SetElement{{Key: []byte{0, 22}}, {Key: []byte{0, 23}}}); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	c.SetDeleteElements(portSet, []nftables.SetElement{{Key: []byte{0, 23}}})

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	elems, err := c.GetSetElements(portSet)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(elems) != 1 {
		t.Fatalf("len(elems) = %d, want 1", len(elems))
	}
	if !bytes.Equal(elems[0].Key, []byte{0, 22}) {
		t.Errorf("elems[0].Key = %v, want 22", elems[0].Key)
	}
}

func TestGetRuleLookupVerdictImmediate(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

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

	set := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(set, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

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
			// [ lookup reg 1 set __set%d ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        set.Name,
				SetID:          set.ID,
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
			// [ immediate reg 2 kek ]
			&expr.Immediate{
				Register: 2,
				Data:     []byte("kek"),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRule(
		&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		},
		&nftables.Chain{
			Name: "forward",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}
	if got, want := len(rules[0].Exprs), 6; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	lookup, lookupOk := rules[0].Exprs[3].(*expr.Lookup)
	if !lookupOk {
		t.Fatalf("Exprs[3] is type %T, want *expr.Lookup", rules[0].Exprs[3])
	}
	if want := (&expr.Lookup{
		SourceRegister: 1,
		SetName:        set.Name,
	}); !reflect.DeepEqual(lookup, want) {
		t.Errorf("lookup expr = %+v, wanted %+v", lookup, want)
	}

	verdict, verdictOk := rules[0].Exprs[4].(*expr.Verdict)
	if !verdictOk {
		t.Fatalf("Exprs[4] is type %T, want *expr.Verdict", rules[0].Exprs[4])
	}
	if want := (&expr.Verdict{
		Kind: expr.VerdictAccept,
	}); !reflect.DeepEqual(verdict, want) {
		t.Errorf("verdict expr = %+v, wanted %+v", verdict, want)
	}

	imm, immOk := rules[0].Exprs[5].(*expr.Immediate)
	if !immOk {
		t.Fatalf("Exprs[4] is type %T, want *expr.Immediate", rules[0].Exprs[5])
	}
	if want := (&expr.Immediate{
		Register: 2,
		Data:     []byte("kek"),
	}); !reflect.DeepEqual(imm, want) {
		t.Errorf("verdict expr = %+v, wanted %+v", imm, want)
	}
}

func TestConfigureNATRedirect(t *testing.T) {
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
		// nft add rule nat prerouting tcp dport 22 redirect to 2222
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\xfc\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x00\x16\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x06\x00\x01\x00\x08\xae\x00\x00\x1c\x00\x01\x80\x0a\x00\x01\x00\x72\x65\x64\x69\x72\x00\x00\x00\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
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

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
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
				Offset:       2, // TODO
				Len:          2, // TODO
			},
			// [ cmp eq reg 1 0x00001600 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x00, 0x16},
			},

			// [ immediate reg 1 0x0000ae08 ]
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(2222),
			},

			// [ redir proto_min reg 1 ]
			&expr.Redir{
				RegisterProtoMin: 1,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureJumpVerdict(t *testing.T) {
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
		// nft add rule nat prerouting tcp dport 1-65535 jump istio_redirect
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x24\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x05\x0c\x00\x03\x80\x06\x00\x01\x00\x00\x01\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x03\x0c\x00\x03\x80\x06\x00\x01\x00\xff\xff\x00\x00\x44\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x30\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x24\x00\x02\x80\x20\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfd\x13\x00\x02\x00\x69\x73\x74\x69\x6f\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x00\x00"),
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

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
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
				Offset:       2, // TODO
				Len:          2, // TODO
			},
			// [ cmp gte reg 1 0x00000100 ]
			&expr.Cmp{
				Op:       expr.CmpOpGte,
				Register: 1,
				Data:     []byte{0x00, 0x01},
			},
			// [ cmp lte reg 1 0x0000ffff ]
			&expr.Cmp{
				Op:       expr.CmpOpLte,
				Register: 1,
				Data:     []byte{0xff, 0xff},
			},

			// [ immediate reg 0 jump -> istio_redirect ]
			&expr.Verdict{
				Kind:  expr.VerdictKind(unix.NFT_JUMP),
				Chain: "istio_redirect",
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureReturnVerdict(t *testing.T) {
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
		// nft add rule nat prerouting meta skgid 1337 return
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x84\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x0b\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x39\x05\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
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

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: []expr.Any{
			// [ meta load skgid => reg 1 ]
			&expr.Meta{Key: expr.MetaKeySKGID, Register: 1},
			// [ cmp eq reg 1 0x00000539 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x39, 0x05, 0x00, 0x00},
			},

			// [ immediate reg 0 return ]
			&expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureRangePort(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule filter forward tcp sport != 2024-2030  return
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain filter forward '{' type filter hook forward priority 0 \; '}'
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule filter forward tcp sport != 2024-2030  return
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xf4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x02\x3c\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x06\x00\x01\x00\x07\xe8\x00\x00\x0c\x00\x04\x80\x06\x00\x01\x00\x07\xee\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
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
			// [ payload load 2b @ transport header + 0 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0, // TODO
				Len:          2, // TODO
			},
			// [ range neq reg 1 0x0000e807 0x0000ee07 ]
			&expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 1,
				FromData: binaryutil.BigEndian.PutUint16(uint16(2024)),
				ToData:   binaryutil.BigEndian.PutUint16(uint16(2030)),
			},
			// [ immediate reg 0 return ]
			&expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureRangeIPv4(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule filter forward ip saddr != 192.168.1.0-192.168.2.0  return
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain filter forward '{' type filter hook forward priority 0 \; '}'
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule filter forward ip saddr != 192.168.1.0-192.168.2.0  return
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xa4\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x3c\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x08\x00\x01\x00\xc0\xa8\x01\x00\x0c\x00\x04\x80\x08\x00\x01\x00\xc0\xa8\x02\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
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
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // TODO
				Len:          4,  // TODO
			},
			// [ range neq reg 1 0x0000e807 0x0000ee07 ]
			&expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 1,
				FromData: net.ParseIP("192.168.1.0").To4(),
				ToData:   net.ParseIP("192.168.2.0").To4(),
			},
			// [ immediate reg 0 return ]
			&expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureRangeIPv6(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule ip6 filter forward ip6 saddr != 2001:0001::1-2001:0002::1 return
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip6 filter
		[]byte("\x0a\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip6 filter forward '{' type filter hook forward priority 0 \; '}'
		[]byte("\x0a\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip6 filter forward ip6 saddr != 2001:0001::1-2001:0002::1 return
		[]byte("\x0a\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xbc\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x08\x08\x00\x04\x00\x00\x00\x00\x10\x54\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x44\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x18\x00\x03\x80\x14\x00\x01\x00\x20\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x18\x00\x04\x80\x14\x00\x01\x00\x20\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
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
		Family: nftables.TableFamilyIPv6,
		Name:   "filter",
	})

	forward := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	ip1 := net.ParseIP("2001:0001::1").To16()
	ip2 := net.ParseIP("2001:0002::1").To16()

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ payload load 16b @ network header + 8 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8,  // TODO
				Len:          16, // TODO
			},
			// [ range neq reg 1 0x01000120 0x00000000 0x00000000 0x01000000 0x02000120 0x00000000 0x00000000 0x01000000 ]
			&expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 1,
				FromData: ip1,
				ToData:   ip2,
			},
			// [ immediate reg 0 return ]
			&expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestSet4(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace-4.21 -f -v -x -s 2048 -etrace=sendto nft add table ip nat
	//
	// Until https://github.com/strace/strace/issues/100 is resolved,
	// you need to use strace 4.21 or apply the patch in the issue.
	//
	// Additional details can be obtained by specifying the --debug=all option
	// when calling nft(8).
	want := [][]byte{

		// batch begin
		[]byte("\x00\x00\x00\x0a"),

		// table ip ipv4table {
		// 	set test-set {
		// 		type inet_service
		// 		flags constant
		// 		elements = { 12000, 12001, 12345, 12346 }
		// 	}
		//
		// 	chain ipv4chain-2 {
		// 		type nat hook prerouting priority dstnat; policy accept;
		// 		tcp dport @test-set
		// 	}
		// }

		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),

		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x03\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x32\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\xff\xff\xff\x9c\x08\x00\x05\x00\x00\x00\x00\x01\x08\x00\x07\x00\x6e\x61\x74\x00"),

		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x0d\x00\x02\x00\x74\x65\x73\x74\x2d\x73\x65\x74\x00\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x0d\x08\x00\x05\x00\x00\x00\x00\x02\x08\x00\x0a\x00\x00\x00\x00\x01\x0c\x00\x09\x80\x08\x00\x01\x00\x00\x00\x00\x04\x0a\x00\x0d\x00\x00\x04\x02\x00\x00\x00\x00\x00"),

		[]byte("\x02\x00\x00\x00\x0d\x00\x02\x00\x74\x65\x73\x74\x2d\x73\x65\x74\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x44\x00\x03\x80\x10\x00\x01\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x2e\xe0\x00\x00\x10\x00\x02\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x2e\xe1\x00\x00\x10\x00\x03\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x30\x39\x00\x00\x10\x00\x04\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x30\x3a\x00\x00"),

		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x32\x00\xbc\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x34\x00\x01\x80\x0b\x00\x01\x00\x6c\x6f\x6f\x6b\x75\x70\x00\x00\x24\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01\x0d\x00\x01\x00\x74\x65\x73\x74\x2d\x73\x65\x74\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01"),

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

	tbl := &nftables.Table{
		Name:   "ipv4table",
		Family: nftables.TableFamilyIPv4,
	}
	defPol := nftables.ChainPolicyAccept
	ch := &nftables.Chain{
		Name:     "ipv4chain-2",
		Table:    tbl,
		Type:     nftables.ChainTypeNAT,
		Priority: nftables.ChainPriorityNATDest,
		Hooknum:  nftables.ChainHookPrerouting,
		Policy:   &defPol,
	}
	set := nftables.Set{
		Anonymous: false,
		Constant:  true,
		Name:      "test-set",
		ID:        uint32(1), //rand.Intn(0xffff)),
		Table:     tbl,
		KeyType:   nftables.TypeInetService,
	}
	c.AddTable(tbl)
	c.AddChain(ch)

	re := []expr.Any{}
	re = append(re, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1})
	re = append(re, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{unix.IPPROTO_TCP},
	})
	re = append(re, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       2, // Offset for a transport protocol header
		Len:          2, // 2 bytes for port
	})
	re = append(re, &expr.Lookup{
		SourceRegister: 1,
		Invert:         false,
		SetID:          set.ID,
		SetName:        set.Name,
	})

	ports := []uint16{12000, 12001, 12345, 12346}
	setElements := make([]nftables.SetElement, len(ports))
	for i := 0; i < len(ports); i++ {
		setElements[i].Key = binaryutil.BigEndian.PutUint16(ports[i])
	}

	if err := c.AddSet(&set, setElements); err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Table: tbl,
		Chain: ch,
		Exprs: re,
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestMasq(t *testing.T) {
	tests := []struct {
		name      string
		chain     *nftables.Chain
		want      [][]byte
		masqExprs []expr.Any
	}{
		{
			name: "Masquerada",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain ip protocol tcp masquerade
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x78\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x14\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x04\x00\x02\x80"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			masqExprs: []expr.Any{
				&expr.Masq{},
			},
		},
		{
			name: "Masquerada with flags",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain ip protocol tcp masquerade random,fully-random,persistent
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x80\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x1c\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x1c"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			masqExprs: []expr.Any{
				&expr.Masq{Random: true, FullyRandom: true, Persistent: true, ToPorts: false},
			},
		},
		{
			name: "Masquerada with 1 port",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain ip protocol tcp masquerade to :1024
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\xac\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x04\x00\x00\x00\x1c\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x0c\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			masqExprs: []expr.Any{
				&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(1024) << 16)},
				&expr.Masq{ToPorts: true, RegProtoMin: 1},
			},
		},
		{
			name: "Masquerada with  port range",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain ip protocol tcp masquerade to :1024-2044
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\xe0\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x04\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x08\x00\x01\x00\x07\xfc\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x02"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			masqExprs: []expr.Any{
				&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint32(uint32(1024) << 16)},
				&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint32(uint32(2044) << 16)},
				&expr.Masq{ToPorts: true, RegProtoMin: 1, RegProtoMax: 2},
			},
		},
	}

	for _, tt := range tests {
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
					if len(tt.want[idx]) == 0 {
						t.Errorf("no want entry for message %d: %x", idx, b)
						continue
					}
					got := b
					if !bytes.Equal(got, tt.want[idx]) {
						t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(tt.want[idx])))
					}
				}
				return req, nil
			},
		}

		filter := c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		})

		tt.chain.Table = filter
		chain := c.AddChain(tt.chain)
		exprs := []expr.Any{
			//  [ payload load 1b @ network header + 9 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
		}
		exprs = append(exprs, tt.masqExprs...)
		c.AddRule(&nftables.Rule{
			Table: filter,
			Chain: chain,
			Exprs: exprs,
		})
		if err := c.Flush(); err != nil {
			t.Fatalf("Test \"%s\" failed with error: %+v", tt.name, err)
		}
	}
}

func TestReject(t *testing.T) {
	tests := []struct {
		name        string
		chain       *nftables.Chain
		want        [][]byte
		rejectExprs []expr.Any
	}{
		{
			name: "Reject",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain reject
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			rejectExprs: []expr.Any{
				&expr.Reject{},
			},
		},
		{
			name: "Reject with tcp reset",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain reject with tcp reset
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x05\x00\x02\x00\x01\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			rejectExprs: []expr.Any{
				&expr.Reject{Type: unix.NFT_REJECT_TCP_RST, Code: unix.NFT_REJECT_TCP_RST},
			},
		},
		{
			name: "Reject with icmp type host-unreachable",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain reject with icmp type host-unreachable
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			rejectExprs: []expr.Any{
				&expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: unix.NFT_REJECT_ICMP_UNREACH},
			},
		},
	}

	for _, tt := range tests {
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
					if len(tt.want[idx]) == 0 {
						t.Errorf("no want entry for message %d: %x", idx, b)
						continue
					}
					got := b
					if !bytes.Equal(got, tt.want[idx]) {
						t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(tt.want[idx])))
					}
				}
				return req, nil
			},
		}

		filter := c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		})

		tt.chain.Table = filter
		chain := c.AddChain(tt.chain)
		c.AddRule(&nftables.Rule{
			Table: filter,
			Chain: chain,
			Exprs: tt.rejectExprs,
		})
		if err := c.Flush(); err != nil {
			t.Fatalf("Test \"%s\" failed with error: %+v", tt.name, err)
		}
	}
}

func TestFib(t *testing.T) {
	tests := []struct {
		name     string
		chain    *nftables.Chain
		want     [][]byte
		fibExprs []expr.Any
	}{
		{
			name: "fib saddr type local",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain fib saddr type local
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x2c\x00\x04\x80\x28\x00\x01\x80\x08\x00\x01\x00\x66\x69\x62\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x03"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			fibExprs: []expr.Any{
				&expr.Fib{
					Register:       1,
					FlagSADDR:      true,
					ResultADDRTYPE: true,
				},
			},
		},
		{
			name: "fib daddr type broadcast",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain fib daddr type broadcast
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x2c\x00\x04\x80\x28\x00\x01\x80\x08\x00\x01\x00\x66\x69\x62\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x03"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			fibExprs: []expr.Any{
				&expr.Fib{
					Register:       1,
					FlagDADDR:      true,
					ResultADDRTYPE: true,
				},
			},
		},
		{
			name: "fib saddr . iif oif missing",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain fib saddr . iif oif missing
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x2c\x00\x04\x80\x28\x00\x01\x80\x08\x00\x01\x00\x66\x69\x62\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x02\x00\x00\x00\x00\x01"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			fibExprs: []expr.Any{
				&expr.Fib{
					Register:  1,
					FlagSADDR: true,
					FlagIIF:   true,
					ResultOIF: true,
				},
			},
		},
	}

	for _, tt := range tests {
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
					if len(tt.want[idx]) == 0 {
						t.Errorf("no want entry for message %d: %x", idx, b)
						continue
					}
					got := b
					if !bytes.Equal(got, tt.want[idx]) {
						t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(tt.want[idx])))
					}
				}
				return req, nil
			},
		}

		filter := c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		})

		tt.chain.Table = filter
		chain := c.AddChain(tt.chain)
		c.AddRule(&nftables.Rule{
			Table: filter,
			Chain: chain,
			Exprs: tt.fibExprs,
		})
		if err := c.Flush(); err != nil {
			t.Fatalf("Test \"%s\" failed with error: %+v", tt.name, err)
		}
	}
}

func TestMap(t *testing.T) {
	tests := []struct {
		name    string
		chain   *nftables.Chain
		want    [][]byte
		set     nftables.Set
		element []nftables.SetElement
	}{
		{
			name: "map inet_service: inet_service 1 element",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add map ip filter test-map  { type inet_service: inet_service\; elements={ 22: 1024 } \; }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0d\x00\x02\x00\x74\x65\x73\x74\x2d\x6d\x61\x70\x00\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x08\x08\x00\x04\x00\x00\x00\x00\x0d\x08\x00\x05\x00\x00\x00\x00\x02\x08\x00\x0a\x00\x00\x00\x00\x01\x08\x00\x06\x00\x00\x00\x00\x0d\x08\x00\x07\x00\x00\x00\x00\x02"),
				[]byte("\x02\x00\x00\x00\x0d\x00\x02\x00\x74\x65\x73\x74\x2d\x6d\x61\x70\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x20\x00\x03\x80\x1c\x00\x01\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x00\x16\x00\x00\x0c\x00\x02\x80\x06\x00\x01\x00\x04\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			set: nftables.Set{
				Name:     "test-map",
				ID:       uint32(1),
				KeyType:  nftables.TypeInetService,
				DataType: nftables.TypeInetService,
				IsMap:    true,
			},
			element: []nftables.SetElement{
				{
					Key: binaryutil.BigEndian.PutUint16(uint16(22)),
					Val: binaryutil.BigEndian.PutUint16(uint16(1024)),
				},
			},
		},
	}

	for _, tt := range tests {
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
					if len(tt.want[idx]) == 0 {
						t.Errorf("no want entry for message %d: %x", idx, b)
						continue
					}
					got := b
					if !bytes.Equal(got, tt.want[idx]) {
						t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(tt.want[idx])))
					}
				}
				return req, nil
			},
		}

		filter := c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		})

		tt.chain.Table = filter
		c.AddChain(tt.chain)
		tt.set.Table = filter
		c.AddSet(&tt.set, tt.element)
		if err := c.Flush(); err != nil {
			t.Fatalf("Test \"%s\" failed with error: %+v", tt.name, err)
		}
	}
}

func TestVmap(t *testing.T) {
	tests := []struct {
		name    string
		chain   *nftables.Chain
		want    [][]byte
		set     nftables.Set
		element []nftables.SetElement
	}{
		{
			name: "map inet_service: drop verdict",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add map ip filter test-vmap  { type inet_service: verdict\; elements={ 22: drop } \; }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0e\x00\x02\x00\x74\x65\x73\x74\x2d\x76\x6d\x61\x70\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x08\x08\x00\x04\x00\x00\x00\x00\x0d\x08\x00\x05\x00\x00\x00\x00\x02\x08\x00\x0a\x00\x00\x00\x00\x01\x08\x00\x06\x00\xff\xff\xff\x00\x08\x00\x07\x00\x00\x00\x00\x00"),
				[]byte("\x02\x00\x00\x00\x0e\x00\x02\x00\x74\x65\x73\x74\x2d\x76\x6d\x61\x70\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x24\x00\x03\x80\x20\x00\x01\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x00\x16\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			set: nftables.Set{
				Name:     "test-vmap",
				ID:       uint32(1),
				KeyType:  nftables.TypeInetService,
				DataType: nftables.TypeVerdict,
				IsMap:    true,
			},
			element: []nftables.SetElement{
				{
					Key: binaryutil.BigEndian.PutUint16(uint16(22)),
					VerdictData: &expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
			},
		}, {
			name: "map inet_service: jump to chain verdict",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add map ip filter test-vmap  { type inet_service: verdict\; elements={ 22: jump fake-chain } \; }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0e\x00\x02\x00\x74\x65\x73\x74\x2d\x76\x6d\x61\x70\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x08\x08\x00\x04\x00\x00\x00\x00\x0d\x08\x00\x05\x00\x00\x00\x00\x02\x08\x00\x0a\x00\x00\x00\x00\x01\x08\x00\x06\x00\xff\xff\xff\x00\x08\x00\x07\x00\x00\x00\x00\x00"),
				[]byte("\x02\x00\x00\x00\x0e\x00\x02\x00\x74\x65\x73\x74\x2d\x76\x6d\x61\x70\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x34\x00\x03\x80\x30\x00\x01\x80\x0c\x00\x01\x80\x06\x00\x01\x00\x00\x16\x00\x00\x20\x00\x02\x80\x1c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfd\x0f\x00\x02\x00\x66\x61\x6b\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			set: nftables.Set{
				Name:     "test-vmap",
				ID:       uint32(1),
				KeyType:  nftables.TypeInetService,
				DataType: nftables.TypeVerdict,
				IsMap:    true,
			},
			element: []nftables.SetElement{
				{
					Key: binaryutil.BigEndian.PutUint16(uint16(22)),
					VerdictData: &expr.Verdict{
						Kind:  unix.NFT_JUMP,
						Chain: "fake-chain",
					},
				},
			},
		},
	}

	for _, tt := range tests {
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
					if len(tt.want[idx]) == 0 {
						t.Errorf("no want entry for message %d: %x", idx, b)
						continue
					}
					got := b
					if !bytes.Equal(got, tt.want[idx]) {
						t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(tt.want[idx])))
					}
				}
				return req, nil
			},
		}

		filter := c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		})

		tt.chain.Table = filter
		c.AddChain(tt.chain)
		tt.set.Table = filter
		c.AddSet(&tt.set, tt.element)
		if err := c.Flush(); err != nil {
			t.Fatalf("Test \"%s\" failed with error: %+v", tt.name, err)
		}
	}
}

func TestJHash(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule filter prerouting mark set jhash ip saddr mod 2
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip filter base-chain { type filter hook prerouting priority 0 \; }
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule filter base_chain mark set jhash ip saddr mod 2 seed 0xfeedcafe offset 1
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\xa8\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x4c\x00\x01\x80\x09\x00\x01\x00\x68\x61\x73\x68\x00\x00\x00\x00\x3c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x08\x00\x04\x00\x00\x00\x00\x02\x08\x00\x05\x00\xfe\xed\xca\xfe\x08\x00\x06\x00\x00\x00\x00\x01\x08\x00\x07\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x03\x00\x00\x00\x00\x01"),
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
		Name:     "base-chain",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 12 => reg 2 ]
			&expr.Payload{
				DestRegister: 2,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			// [ hash reg 1 = jhash(reg 2, 4, 0xfeedcafe) % mod 2 offset 1 ]
			&expr.Hash{
				SourceRegister: 2,
				DestRegister:   1,
				Length:         4,
				Modulus:        2,
				Seed:           4276996862,
				Offset:         1,
				Type:           expr.HashTypeJenkins,
			},
			// [ meta set mark with reg 1 ]
			&expr.Meta{
				Key:            expr.MetaKeyMARK,
				SourceRegister: true,
				Register:       1,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
