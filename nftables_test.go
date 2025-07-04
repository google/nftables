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
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/internal/nftest"
	"github.com/google/nftables/xt"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var enableSysTests = flag.Bool("run_system_tests", false, "Run tests that operate against the live kernel")

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

func expectMessages(t *testing.T, want [][]byte) nftables.ConnOption {
	nextHandle := uint64(1)
	return nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		var replies []netlink.Message
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

			// Generate replies.
			if msg.Header.Flags&netlink.Echo != 0 {
				data := append([]byte{}, msg.Data...)
				switch msg.Header.Type {
				case netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWRULE):
					attrs, _ := netlink.MarshalAttributes([]netlink.Attribute{
						{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(nextHandle)},
					})
					nextHandle++
					data = append(data, attrs...)
				}
				replies = append(replies, netlink.Message{
					Header: msg.Header,
					Data:   data,
				})
			}
		}
		return replies, nil
	})
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func TestRuleOperations(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Name:     "base-chain",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: prerouting,
		Exprs: []expr.Any{
			&expr.Verdict{
				// [ immediate reg 0 drop ]
				Kind: expr.VerdictDrop,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: prerouting,
		Exprs: []expr.Any{
			&expr.Verdict{
				// [ immediate reg 0 drop ]
				Kind: expr.VerdictDrop,
			},
		},
	})

	c.InsertRule(&nftables.Rule{
		Table: filter,
		Chain: prerouting,
		Exprs: []expr.Any{
			&expr.Verdict{
				// [ immediate reg 0 accept ]
				Kind: expr.VerdictAccept,
			},
		},
	})

	c.InsertRule(&nftables.Rule{
		Table: filter,
		Chain: prerouting,
		Exprs: []expr.Any{
			&expr.Verdict{
				// [ immediate reg 0 queue ]
				Kind: expr.VerdictQueue,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	rules, _ := c.GetRules(filter, prerouting)

	want := []expr.VerdictKind{
		expr.VerdictQueue,
		expr.VerdictAccept,
		expr.VerdictDrop,
		expr.VerdictDrop,
	}

	for i, r := range rules {
		rr, _ := r.Exprs[0].(*expr.Verdict)

		if rr.Kind != want[i] {
			t.Fatalf("bad verdict kind at %d", i)
		}
	}

	c.ReplaceRule(&nftables.Rule{
		Table:  filter,
		Chain:  prerouting,
		Handle: rules[2].Handle,
		Exprs: []expr.Any{
			&expr.Verdict{
				// [ immediate reg 0 accept ]
				Kind: expr.VerdictAccept,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table:    filter,
		Chain:    prerouting,
		Position: rules[2].Handle,
		Exprs: []expr.Any{
			&expr.Verdict{
				// [ immediate reg 0 drop ]
				Kind: expr.VerdictDrop,
			},
		},
	})

	c.InsertRule(&nftables.Rule{
		Table:    filter,
		Chain:    prerouting,
		Position: rules[2].Handle,
		Exprs: []expr.Any{
			&expr.Verdict{
				// [ immediate reg 0 queue ]
				Kind: expr.VerdictQueue,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	rules, _ = c.GetRules(filter, prerouting)

	want = []expr.VerdictKind{
		expr.VerdictQueue,
		expr.VerdictAccept,
		expr.VerdictQueue,
		expr.VerdictAccept,
		expr.VerdictDrop,
		expr.VerdictDrop,
	}

	for i, r := range rules {
		rr, _ := r.Exprs[0].(*expr.Verdict)

		if rr.Kind != want[i] {
			t.Fatalf("bad verdict kind at %d", i)
		}
	}
}

func TestRuleHandle(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	var filter *nftables.Table
	var input *nftables.Chain
	var rule2 *nftables.Rule
	tests := [...]struct {
		Name   string
		Func   func()
		Expect []string
	}{
		{
			Name: "delete-rule",
			Func: func() {
				if err := c.DelRule(rule2); err != nil {
					t.Errorf("DelRule failed: %v", err)
				}
			},
			Expect: []string{"1", "3"},
		},
		{
			Name: "add-rule",
			Func: func() {
				c.AddRule(&nftables.Rule{
					Table:      filter,
					Chain:      input,
					Position:   rule2.Handle,
					PositionID: rule2.ID,
					UserData:   []byte("4"),
				})
			},
			Expect: []string{"1", "2", "4", "3"},
		},
		{
			Name: "insert-rule",
			Func: func() {
				c.InsertRule(&nftables.Rule{
					Table:      filter,
					Chain:      input,
					Position:   rule2.Handle,
					PositionID: rule2.ID,
					UserData:   []byte("4"),
				})
			},
			Expect: []string{"1", "4", "2", "3"},
		},
	}

	for _, tt := range tests {
		for _, afterFlush := range []bool{false, true} {
			flushName := map[bool]string{
				false: "-before-flush",
				true:  "-after-flush",
			}
			t.Run(tt.Name+flushName[afterFlush], func(t *testing.T) {
				c.FlushRuleset()
				filter = c.AddTable(&nftables.Table{
					Family: nftables.TableFamilyIPv4,
					Name:   "filter",
				})
				input = c.AddChain(&nftables.Chain{
					Name:     "input",
					Table:    filter,
					Type:     nftables.ChainTypeFilter,
					Hooknum:  nftables.ChainHookInput,
					Priority: nftables.ChainPriorityFilter,
				})
				c.AddRule(&nftables.Rule{
					Table:    filter,
					Chain:    input,
					UserData: []byte("1"),
				})
				rule2 = c.AddRule(&nftables.Rule{
					Table:    filter,
					Chain:    input,
					UserData: []byte("2"),
				})
				c.AddRule(&nftables.Rule{
					Table:    filter,
					Chain:    input,
					UserData: []byte("3"),
				})
				if afterFlush {
					if err := c.Flush(); err != nil {
						t.Errorf("c.Flush() failed: %v", err)
					}
				}
				tt.Func()
				if err := c.Flush(); err != nil {
					t.Errorf("c.Flush() failed: %v", err)
				}

				rules, err := c.GetRules(filter, input)
				if err != nil {
					t.Fatal(err)
				}
				got := []string{}
				for _, rule := range rules {
					got = append(got, string(rule.UserData))
				}
				if !slices.Equal(tt.Expect, got) {
					t.Fatalf("unexpected list of rules: got %v, want %v", got, tt.Expect)
				}
			})
		}
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
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x10\x00\x02\x00\x70\x6f\x73\x74\x72\x6f\x75\x74\x69\x6e\x67\x00\x08\x00\x09\x00\x00\x00\x00\x01\x74\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x07\x08\x00\x01\x00\x00\x00\x00\x01\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x75\x70\x6c\x69\x6e\x6b\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x04\x00\x02\x80"),
		// nft add rule nat prerouting iif uplink0 tcp dport 4070 dnat 192.168.23.2:4080
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x08\x00\x09\x00\x00\x00\x00\x02\x98\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x75\x70\x6c\x69\x6e\x6b\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x0f\xe6\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\xc0\xa8\x17\x02\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x06\x00\x01\x00\x0f\xf0\x00\x00\x30\x00\x01\x80\x08\x00\x01\x00\x6e\x61\x74\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x05\x00\x00\x00\x00\x02"),
		// nft add rule nat prerouting iifname uplink0 udp dport 4070-4090 dnat 192.168.23.2:4070-4090
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x08\x00\x09\x00\x00\x00\x00\x03\xf8\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x06\x08\x00\x01\x00\x00\x00\x00\x01\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x75\x70\x6c\x69\x6e\x6b\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x11\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x05\x0c\x00\x03\x80\x06\x00\x01\x00\x0f\xe6\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x03\x0c\x00\x03\x80\x06\x00\x01\x00\x0f\xfa\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\xc0\xa8\x17\x02\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x06\x00\x01\x00\x0f\xe6\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x03\x0c\x00\x02\x80\x06\x00\x01\x00\x0f\xfa\x00\x00\x38\x00\x01\x80\x08\x00\x01\x00\x6e\x61\x74\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x05\x00\x00\x00\x00\x02\x08\x00\x06\x00\x00\x00\x00\x03"),
		// nft add rule nat prerouting ip daddr 10.0.0.0/24 dnat prefix to 20.0.0.0/24
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x08\x00\x09\x00\x00\x00\x00\x04\x38\x01\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x10\x08\x00\x04\x00\x00\x00\x00\x04\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x0c\x00\x04\x80\x08\x00\x01\x00\xff\xff\xff\x00\x0c\x00\x05\x80\x08\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x0a\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x14\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x08\x00\x01\x00\x14\x00\x00\xff\x38\x00\x01\x80\x08\x00\x01\x00\x6e\x61\x74\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x04\x00\x00\x00\x00\x02\x08\x00\x07\x00\x00\x00\x00\x40"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

	dstipmatch, dstcidrmatch, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	dnatfirstip, dnatlastip, err := nftables.NetFirstAndLastIP("20.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // destination addr offset
				Len:          4,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				// By specifying Xor to 0x0,0x0,0x0,0x0 and Mask to the CIDR mask,
				// the rule will match the CIDR of the IP (e.g in this case 10.0.0.0/24).
				Xor:  []byte{0x0, 0x0, 0x0, 0x0},
				Mask: dstcidrmatch.Mask,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     dstipmatch.To4(),
			},
			&expr.Immediate{
				Register: 1,
				Data:     dnatfirstip,
			},
			&expr.Immediate{
				Register: 2,
				Data:     dnatlastip,
			},
			&expr.NAT{
				Type:       expr.NATTypeDestNAT,
				RegAddrMin: 1,
				RegAddrMax: 2,
				Prefix:     true,
				Family:     uint32(nftables.TableFamilyIPv4),
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
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x10\x00\x02\x00\x70\x6f\x73\x74\x72\x6f\x75\x74\x69\x6e\x67\x00\x08\x00\x09\x00\x00\x00\x00\x01\x78\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\xc0\xa8\x45\x02\x14\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x04\x00\x02\x80"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

func TestMasqMarshalUnmarshal(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})
	postrouting := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    filter,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityFilter,
	})

	min := uint32(1)
	max := uint32(3)
	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: postrouting,
		Exprs: []expr.Any{
			&expr.Immediate{
				Register: min,
				Data:     binaryutil.BigEndian.PutUint16(4070),
			},
			&expr.Immediate{
				Register: max,
				Data:     binaryutil.BigEndian.PutUint16(4090),
			},
			&expr.Masq{
				ToPorts:     true,
				RegProtoMin: min,
				RegProtoMax: max,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(
		&nftables.Table{
			Family: nftables.TableFamilyINet,
			Name:   "filter",
		},
		&nftables.Chain{
			Name: "postrouting",
		},
	)
	if err != nil {
		t.Fatalf("c.GetRules() failed: %v", err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected rule count: got %d, want %d", got, want)
	}

	rule := rules[0]
	if got, want := len(rule.Exprs), 3; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	me, ok := rule.Exprs[2].(*expr.Masq)
	if !ok {
		t.Fatalf("unexpected expression type: got %T, want *expr.Masq", rule.Exprs[2])
	}

	if got, want := me.ToPorts, true; got != want {
		t.Errorf("unexpected masq random flag: got %v, want %v", got, want)
	}

	if got, want := me.RegProtoMin, min; got != want {
		t.Errorf("unexpected reg proto min: got %d, want %d", got, want)
	}

	if got, want := me.RegProtoMax, max; got != want {
		t.Errorf("unexpected reg proto max: got %d, want %d", got, want)
	}
}

func TestExprLogOptions(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	input := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	forward := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	keyGQ := uint32((1 << unix.NFTA_LOG_GROUP) | (1 << unix.NFTA_LOG_QTHRESHOLD) | (1 << unix.NFTA_LOG_SNAPLEN))
	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			&expr.Log{
				Key:        keyGQ,
				QThreshold: uint16(20),
				Group:      uint16(1),
				Snaplen:    uint32(132),
			},
		},
	})

	keyPL := uint32((1 << unix.NFTA_LOG_PREFIX) | (1 << unix.NFTA_LOG_LEVEL) | (1 << unix.NFTA_LOG_FLAGS))
	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			&expr.Log{
				Key:   keyPL,
				Data:  []byte("LOG FORWARD"),
				Level: expr.LogLevelDebug,
				Flags: expr.LogFlagsTCPOpt | expr.LogFlagsIPOpt,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(
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

	le, ok := rule.Exprs[0].(*expr.Log)
	if !ok {
		t.Fatalf("unexpected expression type: got %T, want *expr.Log", rule.Exprs[0])
	}

	if got, want := le.Key, keyGQ; got != want {
		t.Fatalf("unexpected log key: got %d, want %d", got, want)
	}

	if got, want := le.Group, uint16(1); got != want {
		t.Fatalf("unexpected group: got %d, want %d", got, want)
	}

	if got, want := le.QThreshold, uint16(20); got != want {
		t.Fatalf("unexpected queue-threshold: got %d, want %d", got, want)
	}

	if got, want := le.Snaplen, uint32(132); got != want {
		t.Fatalf("unexpected snaplen: got %d, want %d", got, want)
	}

	rules, err = c.GetRules(
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

	rule = rules[0]
	if got, want := len(rule.Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	le, ok = rule.Exprs[0].(*expr.Log)
	if !ok {
		t.Fatalf("unexpected expression type: got %T, want *expr.Log", rule.Exprs[0])
	}

	if got, want := le.Key, keyPL; got != want {
		t.Fatalf("unexpected log key: got %d, want %d", got, want)
	}

	if got, want := string(le.Data), "LOG FORWARD"; got != want {
		t.Fatalf("unexpected prefix data: got %s, want %s", got, want)
	}

	if got, want := le.Level, expr.LogLevelDebug; got != want {
		t.Fatalf("unexpected log level: got %d, want %d", got, want)
	}

	if got, want := le.Flags, expr.LogFlagsTCPOpt|expr.LogFlagsIPOpt; got != want {
		t.Fatalf("unexpected log flags: got %d, want %d", got, want)
	}
}

func TestExprLogPrefix(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	input := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			&expr.Log{
				Key:  1 << unix.NFTA_LOG_PREFIX,
				Data: []byte("LOG INPUT"),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(
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
	if got, want := len(rules[0].Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	logExpr, ok := rules[0].Exprs[0].(*expr.Log)
	if !ok {
		t.Fatalf("Exprs[0] is type %T, want *expr.Log", rules[0].Exprs[0])
	}

	// nftables defaults to warn log level when no level is specified and group is not defined
	// see https://wiki.nftables.org/wiki-nftables/index.php/Logging_traffic
	if got, want := logExpr.Key, uint32((1<<unix.NFTA_LOG_PREFIX)|(1<<unix.NFTA_LOG_LEVEL)); got != want {
		t.Fatalf("unexpected *expr.Log key: got %d, want %d", got, want)
	}
	if got, want := string(logExpr.Data), "LOG INPUT"; got != want {
		t.Fatalf("unexpected *expr.Log data: got %s, want %s", got, want)
	}
	if got, want := logExpr.Level, expr.LogLevelWarning; got != want {
		t.Fatalf("unexpected *expr.Log level: got %d, want %d", got, want)
	}
}

func TestGetRules(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft list chain ip filter forward

	want := [][]byte{
		{0x2, 0x0, 0x0, 0x0, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xa, 0x0, 0x2, 0x0, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x0, 0x0, 0x0},
	}

	// The reply messages come from adding log.Printf("msgs: %#v", msgs) to
	// (*github.com/mdlayher/netlink/Conn).receive
	reply := [][]netlink.Message{
		nil,
		{{Header: netlink.Header{Length: 0x68, Type: 0xa06, Flags: 0x802, Sequence: 0x9acb0443, PID: 0xba38ef3c}, Data: []uint8{0x2, 0x0, 0x0, 0xc, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x0, 0xc, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x30, 0x0, 0x4, 0x0, 0x2c, 0x0, 0x1, 0x0, 0xc, 0x0, 0x1, 0x0, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x0, 0x1c, 0x0, 0x2, 0x0, 0xc, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6d, 0x92, 0x20, 0x20, 0xc, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x48, 0xd9}}},
		{{Header: netlink.Header{Length: 0x14, Type: 0x3, Flags: 0x2, Sequence: 0x9acb0443, PID: 0xba38ef3c}, Data: []uint8{0x0, 0x0, 0x0, 0x0}}},
	}

	c, err := nftables.New(nftables.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
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
		}))
	if err != nil {
		t.Fatal(err)
	}

	rules, err := c.GetRules(
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
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x08\x00\x09\x00\x00\x00\x00\x01\x2c\x00\x04\x80\x28\x00\x01\x80\x0b\x00\x01\x00\x6f\x62\x6a\x72\x65\x66\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x09\x00\x02\x00\x66\x77\x64\x65\x64\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

func TestDeleteCounter(t *testing.T) {
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
		// nft delete counter ip filter fwded
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0a\x00\x02\x00\x66\x77\x64\x65\x64\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x01\x04\x00\x04\x80"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.AddObj(&nftables.CounterObj{
		Table:   &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Name:    "fwded",
		Bytes:   0,
		Packets: 0,
	})

	c.DeleteObject(&nftables.CounterObj{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Name:  "fwded",
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

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x31\x00\x08\x00\x09\x00\x00\x00\x00\x01\x24\x00\x04\x80\x20\x00\x01\x80\x08\x00\x01\x00\x6c\x6f\x67\x00\x14\x00\x02\x80\x0d\x00\x02\x00\x6e\x66\x74\x61\x62\x6c\x65\x73\x00\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{Name: "ipv4chain-1", Type: nftables.ChainTypeFilter},
		Exprs: []expr.Any{
			&expr.Log{
				Key:  1 << unix.NFTA_LOG_PREFIX,
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
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0b\x00\x02\x00\x64\x69\x76\x65\x72\x74\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\xb4\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x06\x00\x01\x00\xc3\xa0\x00\x00\x24\x00\x01\x80\x0b\x00\x01\x00\x74\x70\x72\x6f\x78\x79\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name:     "divert",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityRef(-150),
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

func TestTProxyWithAddrField(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add rule filter divert ip protocol tcp tproxy to 10.10.72.1:50080
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0b\x00\x02\x00\x64\x69\x76\x65\x72\x74\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\xe8\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x0a\x0a\x48\x01\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x06\x00\x01\x00\xc3\xa0\x00\x00\x2c\x00\x01\x80\x0b\x00\x01\x00\x74\x70\x72\x6f\x78\x79\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name:     "divert",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityRef(-150),
		},
		Exprs: []expr.Any{
			//	[ payload load 1b @ network header + 9 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			//	[ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			//	[ immediate reg 1 0x01480a0a ]
			&expr.Immediate{Register: 1, Data: []byte("\x0a\x0a\x48\x01")},
			//	[ immediate reg 2 0x0000a0c3 ]
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(50080)},
			//	[ tproxy ip addr reg 1 port reg 2 ]
			&expr.TProxy{
				Family:      byte(nftables.TableFamilyIPv4),
				TableFamily: byte(nftables.TableFamilyIPv4),
				RegAddr:     1,
				RegPort:     2,
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
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x35\x00\x08\x00\x09\x00\x00\x00\x00\x01\x24\x00\x04\x80\x20\x00\x01\x80\x07\x00\x01\x00\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

func TestSecMarkMarshaling(t *testing.T) {
	// Testing marshaling since secmark requires live selinux tag otherwise
	// errors with conn.Receive: netlink receive: no such file or directory.
	// More information available here:
	// https://git.netfilter.org/nftables/tree/files/examples/secmark.nft?id=26d9cbefb10e6bc3765df7e9e7a4fc3b951a80f3#n6
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// sudo nft add table inet filter
		[]byte("\x01\x00\x00\x00\x0b\x00\x01\x00filter\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// sudo nft add secmark inet filter sshtag '{ ctx "system_u:object_r:ssh_server_packet_t:s0" }'
		[]byte("\x01\x00\x00\x00\x0b\x00\x01\x00filter\x00\x00\x0b\x00\x02\x00sshtag\x00\x00\x08\x00\x03\x00\x00\x00\x00\x080\x00\x04\x80,\x00\x01\x00system_u:object_r:ssh_server_packet_t:s0"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	conn, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})

	sec := &nftables.NamedObj{
		Table: table,
		Name:  "sshtag",
		Type:  nftables.ObjTypeSecMark,
		Obj: &expr.SecMark{
			Ctx: "system_u:object_r:ssh_server_packet_t:s0",
		},
	}
	conn.AddObj(sec)

	if err := conn.Flush(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestSynProxyObject(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})

	syn1 := &nftables.NamedObj{
		Table: table,
		Name:  "https-synproxy",
		Type:  nftables.ObjTypeSynProxy,
		Obj: &expr.SynProxy{
			Mss:       1,
			Wscale:    2,
			Timestamp: true,
			SackPerm:  true,
			// set for equals test below
			MssValueSet:    true,
			WscaleValueSet: true,
		},
	}
	syn2 := &nftables.NamedObj{
		Table: table,
		Name:  "https-synproxy-empty",
		Type:  nftables.ObjTypeSynProxy,
		Obj:   &expr.SynProxy{},
	}
	syn3 := &nftables.NamedObj{
		Table: table,
		Name:  "https-synproxy-zero",
		Type:  nftables.ObjTypeSynProxy,
		Obj: &expr.SynProxy{
			Mss:            0,
			Wscale:         0,
			MssValueSet:    true,
			WscaleValueSet: true,
		},
	}
	conn.AddObj(syn1)
	conn.AddObj(syn2)
	conn.AddObj(syn3)
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	objs, err := conn.GetNamedObjects(table)
	if err != nil {
		t.Errorf("c.GetObjects(table) failed: %v", err)
	}
	if got, want := len(objs), 3; got != want {
		t.Fatalf("received %d objects, expected %d", got, want)
	}

	synObjs := []*nftables.NamedObj{syn1, syn2, syn3}
	for i := 0; i < len(objs); i++ {
		obj := objs[i].(*nftables.NamedObj)
		syn := synObjs[i]
		if got, want := obj.Name, syn.Name; got != want {
			t.Errorf("object %d names are not equal: got %s, want %s", i, got, want)
		}
		if got, want := obj.Type, syn.Type; got != want {
			t.Errorf("object %d types are not equal: got %v, want %v", i, got, want)
		}
		if got, want := obj.Table.Name, syn.Table.Name; got != want {
			t.Errorf("object %d tables are not equal: got %s, want %s", i, got, want)
		}
		sp1 := obj.Obj.(*expr.SynProxy)
		sp2 := syn.Obj.(*expr.SynProxy)
		if got, want := sp1.Mss, sp2.Mss; got != want {
			t.Errorf("object %d mss' are not equal: got %d, want %d", i, got, want)
		}
		if got, want := sp1.Wscale, sp2.Wscale; got != want {
			t.Errorf("object %d wscales are not equal: got %d, want %d", i, got, want)
		}
		if got, want := sp1.Timestamp, sp2.Timestamp; got != want {
			t.Errorf("object %d timestamp flags are not equal: got %v, want %v", i, got, want)
		}
		if got, want := sp1.SackPerm, sp2.SackPerm; got != want {
			t.Errorf("object %d sack-perm flags are not equal: got %v, want %v", i, got, want)
		}
		if got, want := sp1.MssValueSet, sp2.MssValueSet; got != want {
			t.Errorf("object %d MssValueSet flags are not equal: got %v, want %v", i, got, want)
		}
		if got, want := sp1.WscaleValueSet, sp2.WscaleValueSet; got != want {
			t.Errorf("object %d WscaleValueSet flags are not equal: got %v, want %v", i, got, want)
		}
		if got, want := sp1.Ecn, sp2.Ecn; got != want {
			t.Errorf("object %d Ecn flags are not equal: got %v, want %v", i, got, want)
		}
	}
}

func TestCtTimeout(t *testing.T) {
	t.Parallel()
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	tests := [...]struct {
		Name   string
		Input  expr.CtTimeout
		Expect expr.CtTimeout
	}{
		{
			Name:  "timeout-blank-tcp-policy",
			Input: expr.CtTimeout{L4Proto: unix.IPPROTO_TCP},
			Expect: expr.CtTimeout{
				L4Proto: unix.IPPROTO_TCP,
				L3Proto: unix.NFPROTO_UNSPEC,
				Policy:  expr.CtStateTCPTimeoutDefaults,
			},
		},
		{
			Name:  "timeout-blank-udp-policy",
			Input: expr.CtTimeout{L4Proto: unix.IPPROTO_UDP},
			Expect: expr.CtTimeout{
				L4Proto: unix.IPPROTO_UDP,
				L3Proto: unix.NFPROTO_UNSPEC,
				Policy:  expr.CtStateUDPTimeoutDefaults,
			},
		},
		{
			Name: "timeout-partial-tcp-policy",
			Input: expr.CtTimeout{
				L4Proto: unix.IPPROTO_TCP,
				L3Proto: unix.NFPROTO_IPV4,
				Policy: expr.CtStatePolicyTimeout{
					expr.CtStateTCPSYNSENT:     100,
					expr.CtStateTCPESTABLISHED: 5,
					expr.CtStateTCPCLOSEWAIT:   9,
				},
			},
			Expect: expr.CtTimeout{
				L4Proto: unix.IPPROTO_TCP,
				L3Proto: unix.NFPROTO_IPV4,
				Policy: expr.CtStatePolicyTimeout{
					expr.CtStateTCPSYNSENT:     100,
					expr.CtStateTCPSYNRECV:     60,
					expr.CtStateTCPESTABLISHED: 5,
					expr.CtStateTCPFINWAIT:     120,
					expr.CtStateTCPCLOSEWAIT:   9,
					expr.CtStateTCPLASTACK:     30,
					expr.CtStateTCPTIMEWAIT:    120,
					expr.CtStateTCPCLOSE:       10,
					expr.CtStateTCPSYNSENT2:    120,
					expr.CtStateTCPRETRANS:     300,
					expr.CtStateTCPUNACK:       300,
				},
			},
		},
		{
			Name: "timeout-complete-udp-policy",
			Input: expr.CtTimeout{
				L4Proto: unix.IPPROTO_UDP,
				L3Proto: unix.NFPROTO_IPV6,
				Policy: expr.CtStatePolicyTimeout{
					expr.CtStateUDPUNREPLIED: 500,
					expr.CtStateUDPREPLIED:   10000,
				},
			},
			Expect: expr.CtTimeout{
				L4Proto: unix.IPPROTO_UDP,
				L3Proto: unix.NFPROTO_IPV6,
				Policy: expr.CtStatePolicyTimeout{
					expr.CtStateUDPUNREPLIED: 500,
					expr.CtStateUDPREPLIED:   10000,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctt1 := conn.AddObj(&nftables.NamedObj{
				Table: table,
				Name:  tt.Name,
				Type:  nftables.ObjTypeCtTimeout,
				Obj:   &tt.Input,
			})

			if err := conn.Flush(); err != nil {
				t.Fatal(err)
			}

			obj, err := conn.GetObject(ctt1)
			if err != nil {
				t.Errorf("c.GetObject(ctt1) failed: %v failed", err)
			}

			ctt2, ok := obj.(*nftables.NamedObj)
			if !ok {
				t.Fatalf("unexpected type: got %T, want *nftables.NamedObj", ctt2)
			}

			o1 := ctt2.Obj.(*expr.CtTimeout)
			o2 := &tt.Expect
			if got, want := o1.L3Proto, o2.L3Proto; got != want {
				t.Fatalf("unexpected l3proto: got %d, want %d", got, want)
			}

			if got, want := o1.L4Proto, o2.L4Proto; got != want {
				t.Fatalf("unexpected l4proto: got %d, want %d", got, want)
			}

			if got, want := o1.Policy, o2.Policy; !reflect.DeepEqual(got, want) {
				t.Fatalf("unexpected policy: got %v, want %v", got, want)
			}
		})
	}
}

func TestCtExpect(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	cte := &nftables.NamedObj{
		Table: table,
		Name:  "expect",
		Type:  nftables.ObjTypeCtExpect,
		Obj: &expr.CtExpect{
			L3Proto: unix.NFPROTO_IPV4,
			L4Proto: unix.IPPROTO_TCP,
			DPort:   53,
			Timeout: 20,
			Size:    100,
		},
	}

	conn.AddObj(cte)
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	objs, err := conn.GetNamedObjects(table)
	if err != nil {
		t.Errorf("c.GetObjects(table) failed: %v", err)
	}

	if got, want := len(objs), 1; got != want {
		t.Fatalf("received %d objects, expected %d", got, want)
	}

	obj := objs[0].(*nftables.NamedObj)
	if got, want := obj.Name, cte.Name; got != want {
		t.Errorf("object names are not equal: got %s, want %s", got, want)
	}
	if got, want := obj.Type, cte.Type; got != want {
		t.Errorf("object types are not equal: got %v, want %v", got, want)
	}
	if got, want := obj.Table.Name, cte.Table.Name; got != want {
		t.Errorf("object tables are not equal: got %s, want %s", got, want)
	}

	ce1 := obj.Obj.(*expr.CtExpect)
	ce2 := cte.Obj.(*expr.CtExpect)
	if got, want := ce1.L3Proto, ce2.L3Proto; got != want {
		t.Errorf("object l3proto not equal: got %d, want %d", got, want)
	}
	if got, want := ce1.L4Proto, ce2.L4Proto; got != want {
		t.Errorf("object l4proto not equal: got %d, want %d", got, want)
	}
	if got, want := ce1.DPort, ce2.DPort; got != want {
		t.Errorf("object dport not equal: got %d, want %d", got, want)
	}
	if got, want := ce1.Size, ce2.Size; got != want {
		t.Errorf("object Size not equal: got %d, want %d", got, want)
	}
	if got, want := ce1.Timeout, ce2.Timeout; got != want {
		t.Errorf("object timeout not equal: got %d, want %d", got, want)
	}
}

func TestCtHelper(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	cthelp1 := conn.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  "ftp-standard",
		Type:  nftables.ObjTypeCtHelper,
		Obj: &expr.CtHelper{
			Name:    "ftp",
			L4Proto: unix.IPPROTO_TCP,
			L3Proto: unix.NFPROTO_IPV4,
		},
	})

	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	obj1, err := conn.GetObject(cthelp1)
	if err != nil {
		t.Errorf("c.GetObject(cthelp1) failed: %v failed", err)
	}

	helper, ok := obj1.(*nftables.NamedObj)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *nftables.NamedObj", obj1)
	}

	if got, want := helper.Name, "ftp-standard"; got != want {
		t.Fatalf("unexpected counter name: got %s, want %s", got, want)
	}

	if _, err = conn.ResetObject(cthelp1); err != nil {
		t.Errorf("c.ResetObjects(cthelp1) failed: %v failed", err)
	}

	obj1, err = conn.GetObject(cthelp1)
	if err != nil {
		t.Errorf("c.GetObject(cthelp1) failed: %v failed", err)
	}

	help := obj1.(*nftables.NamedObj).Obj.(*expr.CtHelper)
	if got, want := help.L4Proto, uint8(unix.IPPROTO_TCP); got != want {
		t.Errorf("unexpected l4proto number: got %d, want %d", got, want)
	}

	if got, want := help.L3Proto, uint16(unix.NFPROTO_IPV4); got != want {
		t.Errorf("unexpected l3proto number: got %d, want %d", got, want)
	}
}

func TestCtSet(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// sudo nft add rule filter forward ct mark set 1
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x08\x00\x09\x00\x00\x00\x00\x01\x50\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x01\x00\x00\x00\x20\x00\x01\x80\x07\x00\x01\x00\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x04\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

func TestCtStat(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// ct state established,related accept
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0b\x00\x02\x00\x6f\x75\x74\x70\x75\x74\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\xc4\x00\x04\x80\x20\x00\x01\x80\x07\x00\x01\x00\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x00\x08\x00\x01\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x0c\x00\x04\x80\x08\x00\x01\x00\x06\x00\x00\x00\x0c\x00\x05\x80\x08\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x08\x00\x01\x00\x00\x00\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}
	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name: "output",
		},
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
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
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x31\x00\x08\x00\x09\x00\x00\x00\x00\x01\xa8\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x0c\x00\x04\x80\x05\x00\x01\x00\xf0\x00\x00\x00\x0c\x00\x05\x80\x05\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x60\x00\x00\x00\x0c\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x02"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Position: 2,
		Table:    &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name:     "ipv4chain-1",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityRef(0),
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

func TestLastingConnection(t *testing.T) {
	testdialerr := errors.New("test dial sentinel error")
	dialCount := 0
	c, err := nftables.New(
		nftables.AsLasting(),
		nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
			dialCount++
			return nil, testdialerr
		}))
	if err != nil {
		t.Errorf("creating lasting netlink connection failed %v", err)
		return
	}
	defer func() {
		if err := c.CloseLasting(); err != nil {
			t.Errorf("closing lasting netlink connection failed %v", err)
		}
	}()

	_, err = c.ListTables()
	if !errors.Is(err, testdialerr) {
		t.Errorf("non-testdialerr error returned from TestDial %v", err)
		return
	}
	if dialCount != 1 {
		t.Errorf("internal test error with TestDial invocations %v", dialCount)
		return
	}

	// While a lasting netlink connection is open, replacing TestDial must be
	// ineffective as there is no need to dial again and activating a new
	// TestDial function. The newly set TestDial function must be getting
	// ignored.
	c.TestDial = func(req []netlink.Message) ([]netlink.Message, error) {
		dialCount--
		return nil, errors.New("transient netlink connection error")
	}
	_, err = c.ListTables()
	if !errors.Is(err, testdialerr) {
		t.Errorf("non-testdialerr error returned from TestDial %v", err)
		return
	}
	if dialCount != 2 {
		t.Errorf("internal test error with TestDial invocations %v", dialCount)
		return
	}

	for i := 0; i < 2; i++ {
		err = c.CloseLasting()
		if err != nil {
			t.Errorf("closing lasting netlink connection failed in attempt no. %d: %v", i, err)
			return
		}
	}
	_, err = c.ListTables()
	if errors.Is(err, testdialerr) {
		t.Error("testdialerr error returned from TestDial when expecting different error")
		return
	}
	if dialCount != 1 {
		t.Errorf("internal test error with TestDial invocations %v", dialCount)
		return
	}

	// fall into defer'ed second CloseLasting which must not cause any errors.
}

func TestListChains(t *testing.T) {
	polDrop := nftables.ChainPolicyDrop
	polAcpt := nftables.ChainPolicyAccept
	reply := [][]byte{
		// chain input { type filter hook input priority filter; policy accept; }
		[]byte("\x70\x00\x00\x00\x03\x0a\x02\x00\x00\x00\x00\x00\xb8\x76\x02\x00\x01\x00\x00\xc3\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x0a\x00\x03\x00\x69\x6e\x70\x75\x74\x00\x00\x00\x14\x00\x04\x00\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x08\x00\x05\x00\x00\x00\x00\x01\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x0a\x00\x00\x00\x00\x01\x08\x00\x06\x00\x00\x00\x00\x00"),
		// chain forward { type filter hook forward priority filter; policy drop; }
		[]byte("\x70\x00\x00\x00\x03\x0a\x02\x00\x00\x00\x00\x01\xb8\x76\x02\x00\x01\x00\x00\xc3\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x02\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x00\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x08\x00\x05\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x0a\x00\x00\x00\x00\x01\x08\x00\x06\x00\x00\x00\x00\x00"),
		// chain output { type filter hook output priority filter; policy accept; }
		[]byte("\x70\x00\x00\x00\x03\x0a\x02\x00\x00\x00\x00\x02\xb8\x76\x02\x00\x01\x00\x00\xc3\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x03\x0b\x00\x03\x00\x6f\x75\x74\x70\x75\x74\x00\x00\x14\x00\x04\x00\x08\x00\x01\x00\x00\x00\x00\x03\x08\x00\x02\x00\x00\x00\x00\x00\x08\x00\x05\x00\x00\x00\x00\x01\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x0a\x00\x00\x00\x00\x01\x08\x00\x06\x00\x00\x00\x00\x00"),
		// chain undef { counter packets 56235 bytes 175436495 return }
		[]byte("\x40\x00\x00\x00\x03\x0a\x02\x00\x00\x00\x00\x03\xb8\x76\x02\x00\x01\x00\x00\xc3\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x04\x0a\x00\x03\x00\x75\x6e\x64\x65\x66\x00\x00\x00\x08\x00\x06\x00\x00\x00\x00\x01"),
		[]byte("\x14\x00\x00\x00\x03\x00\x02\x00\x00\x00\x00\x04\xb8\x76\x02\x00\x00\x00\x00\x00"),
	}

	want := []*nftables.Chain{
		{
			Name:     "input",
			Hooknum:  nftables.ChainHookInput,
			Priority: nftables.ChainPriorityFilter,
			Type:     nftables.ChainTypeFilter,
			Policy:   &polAcpt,
		},
		{
			Name:     "forward",
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
			Type:     nftables.ChainTypeFilter,
			Policy:   &polDrop,
		},
		{
			Name:     "output",
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityFilter,
			Type:     nftables.ChainTypeFilter,
			Policy:   &polAcpt,
		},
		{
			Name:     "undef",
			Hooknum:  nil,
			Priority: nil,
			Policy:   nil,
		},
	}

	c, err := nftables.New(nftables.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			msgReply := make([]netlink.Message, len(reply))
			for i, r := range reply {
				nm := &netlink.Message{}
				nm.UnmarshalBinary(r)
				nm.Header.Sequence = req[0].Header.Sequence
				nm.Header.PID = req[0].Header.PID
				msgReply[i] = *nm
			}
			return msgReply, nil
		}))
	if err != nil {
		t.Fatal(err)
	}

	chains, err := c.ListChains()
	if err != nil {
		t.Errorf("error returned from TestDial %v", err)
		return
	}

	if len(chains) != len(want) {
		t.Errorf("number of chains %d != number of want %d", len(chains), len(want))
		return
	}

	validate := func(got interface{}, want interface{}, name string, index int) {
		if got != want {
			t.Errorf("chain %d: chain %s mismatch, got %v want %v", index, name, got, want)
		}
	}

	for i, chain := range chains {
		validate(chain.Name, want[i].Name, "name", i)
		if want[i].Hooknum != nil && chain.Hooknum != nil {
			validate(*chain.Hooknum, *want[i].Hooknum, "hooknum value", i)
		} else {
			validate(chain.Hooknum, want[i].Hooknum, "hooknum pointer", i)
		}
		if want[i].Priority != nil && chain.Priority != nil {
			validate(*chain.Priority, *want[i].Priority, "priority value", i)
		} else {
			validate(chain.Priority, want[i].Priority, "priority pointer", i)
		}
		validate(chain.Type, want[i].Type, "type", i)

		if want[i].Policy != nil && chain.Policy != nil {
			validate(*chain.Policy, *want[i].Policy, "policy value", i)
		} else {
			validate(chain.Policy, want[i].Policy, "policy pointer", i)
		}
	}
}

func TestListChainByName(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "chain_test",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter",
		Table: table,
	}
	conn.AddChain(c)

	if err := conn.Flush(); err != nil {
		t.Errorf("conn.Flush() failed: %v", err)
	}

	cr, err := conn.ListChain(tr, c.Name)
	if err != nil {
		t.Fatalf("conn.ListChain() failed: %v", err)
	}

	if got, want := cr.Name, c.Name; got != want {
		t.Fatalf("got chain %s, want chain %s", got, want)
	}

	if got, want := cr.Table.Name, table.Name; got != want {
		t.Fatalf("got chain table %s, want chain table %s", got, want)
	}
}

func TestListChainByNameUsingLasting(t *testing.T) {
	_, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	conn, err := nftables.New(nftables.WithNetNSFd(int(newNS)), nftables.AsLasting())
	if err != nil {
		t.Fatalf("nftables.New() failed: %v", err)
	}
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "chain_test_lasting",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter_lasting",
		Table: table,
	}
	conn.AddChain(c)

	if err := conn.Flush(); err != nil {
		t.Errorf("conn.Flush() failed: %v", err)
	}

	cr, err := conn.ListChain(tr, c.Name)
	if err != nil {
		t.Fatalf("conn.ListChain() failed: %v", err)
	}

	if got, want := cr.Name, c.Name; got != want {
		t.Fatalf("got chain %s, want chain %s", got, want)
	}

	if got, want := cr.Table.Name, table.Name; got != want {
		t.Fatalf("got chain table %s, want chain table %s", got, want)
	}
}

func TestListTableByName(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table1 := &nftables.Table{
		Name:   "table_test",
		Family: nftables.TableFamilyIPv4,
	}
	conn.AddTable(table1)
	table2 := &nftables.Table{
		Name:   "table_test_inet",
		Family: nftables.TableFamilyINet,
	}
	conn.AddTable(table2)
	table3 := &nftables.Table{
		Name:   table1.Name,
		Family: nftables.TableFamilyINet,
	}
	conn.AddTable(table3)

	if err := conn.Flush(); err != nil {
		t.Errorf("conn.Flush() failed: %v", err)
	}

	tr, err := conn.ListTable(table1.Name)
	if err != nil {
		t.Fatalf("conn.ListTable() failed: %v", err)
	}

	if got, want := tr.Name, table1.Name; got != want {
		t.Fatalf("got table %s, want table %s", got, want)
	}

	// not specifying table family should return family ipv4
	tr, err = conn.ListTable(table3.Name)
	if err != nil {
		t.Fatalf("conn.ListTable() failed: %v", err)
	}
	if got, want := tr.Name, table1.Name; got != want {
		t.Fatalf("got table %s, want table %s", got, want)
	}
	if got, want := tr.Family, table1.Family; got != want {
		t.Fatalf("got table family %v, want table family %v", got, want)
	}

	// specifying correct INet family
	tr, err = conn.ListTableOfFamily(table3.Name, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("conn.ListTable() failed: %v", err)
	}
	if got, want := tr.Name, table3.Name; got != want {
		t.Fatalf("got table %s, want table %s", got, want)
	}
	if got, want := tr.Family, table3.Family; got != want {
		t.Fatalf("got table family %v, want table family %v", got, want)
	}

	// not specifying correct family should return err since no table in ipv4
	if _, err = conn.ListTable(table2.Name); err == nil {
		t.Fatalf("conn.ListTable() should have failed")
	}

	// specifying correct INet family
	tr, err = conn.ListTableOfFamily(table2.Name, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("conn.ListTable() failed: %v", err)
	}
	if got, want := tr.Name, table2.Name; got != want {
		t.Fatalf("got table %s, want table %s", got, want)
	}
	if got, want := tr.Family, table2.Family; got != want {
		t.Fatalf("got table family %v, want table family %v", got, want)
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
				Priority: nftables.ChainPriorityRef(0),
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
		c, err := nftables.New(expectMessages(t, tt.want))
		if err != nil {
			t.Fatal(err)
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
				Priority: nftables.ChainPriorityRef(0),
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
		c, err := nftables.New(expectMessages(t, tt.want))
		if err != nil {
			t.Fatal(err)
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
		{0x2, 0x0, 0x0, 0x0, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xa, 0x0, 0x2, 0x0, 0x66, 0x77, 0x64, 0x65, 0x64, 0x0, 0x0, 0x0, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x1},
	}

	// The reply messages come from adding log.Printf("msgs: %#v", msgs) to
	// (*github.com/mdlayher/netlink/Conn).receive
	reply := [][]netlink.Message{
		nil,
		{{Header: netlink.Header{Length: 0x64, Type: 0xa12, Flags: 0x802, Sequence: 0x9acb0443, PID: 0xde9}, Data: []uint8{0x2, 0x0, 0x0, 0x10, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xa, 0x0, 0x2, 0x0, 0x66, 0x77, 0x64, 0x65, 0x64, 0x0, 0x0, 0x0, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1c, 0x0, 0x4, 0x0, 0xc, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x61, 0xc, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0xc, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}}},
		{{Header: netlink.Header{Length: 0x14, Type: 0x3, Flags: 0x2, Sequence: 0x9acb0443, PID: 0xde9}, Data: []uint8{0x0, 0x0, 0x0, 0x0}}},
		{{Header: netlink.Header{Length: 36, Type: netlink.Error, Flags: 0x100, Sequence: 0x9acb0443, PID: 0xde9}, Data: []uint8{0, 0, 0, 0, 88, 0, 0, 0, 12, 10, 5, 4, 143, 109, 199, 146, 236, 9, 0, 0}}},
	}

	c, err := nftables.New(nftables.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
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
		}))
	if err != nil {
		t.Fatal(err)
	}

	filter := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	obj, err := c.ResetObject(&nftables.NamedObj{
		Table: filter,
		Name:  "fwded",
		Type:  nftables.ObjTypeCounter,
	})
	if err != nil {
		t.Fatal(err)
	}

	co, ok := obj.(*nftables.NamedObj)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *nftables.ObjAttr", obj)
	}
	if got, want := co.Table.Name, filter.Name; got != want {
		t.Errorf("unexpected table name: got %q, want %q", got, want)
	}
	if got, want := co.Table.Family, filter.Family; got != want {
		t.Errorf("unexpected table family: got %d, want %d", got, want)
	}
	o, ok := co.Obj.(*expr.Counter)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *expr.Counter", o)
	}
	if got, want := o.Packets, uint64(9); got != want {
		t.Errorf("unexpected number of packets: got %d, want %d", got, want)
	}
	if got, want := o.Bytes, uint64(1121); got != want {
		t.Errorf("unexpected number of bytes: got %d, want %d", got, want)
	}
}

func TestGetResetNamedObj(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	c.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  "fwded1",
		Type:  nftables.ObjTypeCounter,
		Obj: &expr.Counter{
			Bytes:   1,
			Packets: 1,
		},
	})

	c.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  "fwded2",
		Type:  nftables.ObjTypeQuota,
		Obj: &expr.Quota{
			Consumed: 1,
			Over:     true,
			Bytes:    0x6400,
		},
	})

	c.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  "fwded3",
		Type:  nftables.ObjTypeConnLimit,
		Obj: &expr.Connlimit{
			Count: 20,
			Flags: 1,
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	objsNamed, err := c.GetNamedObjects(table)
	if err != nil {
		t.Errorf("c.GetNamedObjects(table) failed: %v failed", err)
	}

	if got := len(objsNamed); got != 3 {
		t.Fatalf("unexpected number of objects: got %d, want %d", got, 3)
	}

	for _, o := range objsNamed {
		switch v := o.(type) {
		case *nftables.NamedObj:
		default:
			t.Fatalf("unexpected type in objsNamed: got %v, want *nftables.NamedObj", v)
		}
	}

	objsReset, err := c.ResetNamedObjects(table)
	if err != nil {
		t.Errorf("c.ResetObjects(table) failed: %v failed", err)
	}

	for _, o := range objsReset {
		switch v := o.(type) {
		case *nftables.NamedObj:
		default:
			t.Fatalf("unexpected type in objsReset: got %v, want *nftables.NamedObj", v)
		}
	}
}

func TestObjAPI(t *testing.T) {
	if os.Getenv("TRAVIS") == "true" {
		t.SkipNow()
	}

	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	tableOther := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "foo",
	})

	chain := c.AddChain(&nftables.Chain{
		Name:     "chain",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityFilter,
	})

	counter1 := c.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  "fwded1",
		Type:  nftables.ObjTypeCounter,
		Obj: &expr.Counter{
			Bytes:   1,
			Packets: 1,
		},
	})

	counter2 := c.AddObj(&nftables.NamedObj{
		Table: table,
		Name:  "fwded2",
		Type:  nftables.ObjTypeCounter,
		Obj: &expr.Counter{
			Bytes:   1,
			Packets: 1,
		},
	})

	c.AddObj(&nftables.NamedObj{
		Table: tableOther,
		Name:  "fwdedOther",
		Type:  nftables.ObjTypeCounter,
		Obj: &expr.Counter{
			Bytes:   0,
			Packets: 0,
		},
	})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Objref{
				Type: 1,
				Name: "fwded1",
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	objs, err := c.GetObjects(table)
	if err != nil {
		t.Errorf("c.GetObjects(table) failed: %v failed", err)
	}

	if got := len(objs); got != 2 {
		t.Fatalf("unexpected number of objects: got %d, want %d", got, 2)
	}

	objsOther, err := c.GetObjects(tableOther)
	if err != nil {
		t.Errorf("c.GetObjects(tableOther) failed: %v failed", err)
	}

	if got := len(objsOther); got != 1 {
		t.Fatalf("unexpected number of objects: got %d, want %d", got, 1)
	}

	obj1, err := c.GetObject(counter1)
	if err != nil {
		t.Errorf("c.GetObject(counter1) failed: %v failed", err)
	}

	rcounter1, ok := obj1.(*nftables.NamedObj)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *nftables.ObjAttr", obj1)
	}

	if rcounter1.Name != "fwded1" {
		t.Fatalf("unexpected counter name: got %s, want %s", rcounter1.Name, "fwded1")
	}

	obj2, err := c.GetObject(counter2)
	if err != nil {
		t.Errorf("c.GetObject(counter2) failed: %v failed", err)
	}

	rcounter2, ok := obj2.(*nftables.NamedObj)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *nftables.CounterObj", obj2)
	}

	if rcounter2.Name != "fwded2" {
		t.Fatalf("unexpected counter name: got %s, want %s", rcounter2.Name, "fwded2")
	}

	_, err = c.ResetObject(counter1)

	if err != nil {
		t.Errorf("c.ResetObjects(table) failed: %v failed", err)
	}

	obj1, err = c.GetObject(counter1)

	if err != nil {
		t.Errorf("c.GetObject(counter1) failed: %v failed", err)
	}

	if counter1 := obj1.(*nftables.NamedObj).Obj.(*expr.Counter); counter1.Packets > 0 {
		t.Errorf("unexpected packets number: got %d, want %d", counter1.Packets, 0)
	}

	obj2, err = c.GetObject(counter2)

	if err != nil {
		t.Errorf("c.GetObject(counter2) failed: %v failed", err)
	}

	if counter2 := obj2.(*nftables.NamedObj).Obj.(*expr.Counter); counter2.Packets != 1 {
		t.Errorf("unexpected packets number: got %d, want %d", counter2.Packets, 1)
	}

	legacy, err := c.GetObj(counter1)
	if err != nil {
		t.Errorf("c.GetObj(counter1) failed: %v failed", err)
	}

	if len(legacy) != 2 {
		t.Errorf("unexpected number of objects: got %d, want %d", len(legacy), 2)
	}

	legacyReset, err := c.GetObjReset(counter1)
	if err != nil {
		t.Errorf("c.GetObjReset(counter1) failed: %v failed", err)
	}

	if len(legacyReset) != 2 {
		t.Errorf("unexpected number of objects: got %d, want %d", len(legacyReset), 2)
	}
}

func TestDeleteLegacyQuotaObj(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "quota_demo",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter",
		Table: table,
	}
	conn.AddChain(c)

	o := &nftables.QuotaObj{
		Table:    tr,
		Name:     "q_test",
		Bytes:    0x06400000,
		Consumed: 0,
		Over:     true,
	}
	conn.AddObj(o)

	if err := conn.Flush(); err != nil {
		t.Fatalf("conn.Flush() failed: %v", err)
	}

	obj, err := conn.GetObj(&nftables.QuotaObj{
		Table: table,
		Name:  "q_test",
	})
	if err != nil {
		t.Fatalf("conn.GetObj() failed: %v", err)
	}

	if got, want := len(obj), 1; got != want {
		t.Fatalf("unexpected number of objects: got %d, want %d", got, want)
	}

	if got, want := obj[0], o; !reflect.DeepEqual(got, want) {
		t.Errorf("got = %+v, want = %+v", got, want)
	}

	conn.DeleteObject(&nftables.QuotaObj{
		Table: tr,
		Name:  "q_test",
	})

	if err := conn.Flush(); err != nil {
		t.Fatalf("conn.Flush() failed: %v", err)
	}

	obj, err = conn.GetObj(&nftables.QuotaObj{
		Table: table,
		Name:  "q_test",
	})
	if err != nil {
		t.Fatalf("conn.GetObj() failed: %v", err)
	}
	if got, want := len(obj), 0; got != want {
		t.Fatalf("unexpected object list length: got %d, want %d", got, want)
	}
}

func TestAddLegacyQuotaObj(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "quota_demo",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter",
		Table: table,
	}
	conn.AddChain(c)

	o := &nftables.QuotaObj{
		Table:    tr,
		Name:     "q_test",
		Bytes:    0x06400000,
		Consumed: 0,
		Over:     true,
	}
	conn.AddObj(o)

	if err := conn.Flush(); err != nil {
		t.Errorf("conn.Flush() failed: %v", err)
	}

	obj, err := conn.GetObj(&nftables.QuotaObj{
		Table: table,
		Name:  "q_test",
	})
	if err != nil {
		t.Fatalf("conn.GetObj() failed: %v", err)
	}

	if got, want := len(obj), 1; got != want {
		t.Fatalf("unexpected object list length: got %d, want %d", got, want)
	}

	o1, ok := obj[0].(*nftables.QuotaObj)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *QuotaObj", obj[0])
	}
	if got, want := o1.Name, o.Name; got != want {
		t.Fatalf("quota name mismatch: got %s, want %s", got, want)
	}
	if got, want := o1.Bytes, o.Bytes; got != want {
		t.Fatalf("quota bytes mismatch: got %d, want %d", got, want)
	}
	if got, want := o1.Consumed, o.Consumed; got != want {
		t.Fatalf("quota consumed mismatch: got %d, want %d", got, want)
	}
	if got, want := o1.Over, o.Over; got != want {
		t.Fatalf("quota over mismatch: got %v, want %v", got, want)
	}
}

func TestAddLegacyQuotaObjRef(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "quota_demo",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter",
		Table: table,
	}
	conn.AddChain(c)

	o := &nftables.QuotaObj{
		Table:    tr,
		Name:     "q_test",
		Bytes:    0x06400000,
		Consumed: 0,
		Over:     true,
	}
	conn.AddObj(o)

	r := &nftables.Rule{
		Table: table,
		Chain: c,
		Exprs: []expr.Any{
			&expr.Objref{
				Type: 2,
				Name: "q_test",
			},
		},
	}
	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		t.Fatalf("failed to flush: %v", err)
	}

	rules, err := conn.GetRules(table, c)
	if err != nil {
		t.Fatalf("failed to get rules: %v", err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}
	if got, want := len(rules[0].Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	objref, ok := rules[0].Exprs[0].(*expr.Objref)
	if !ok {
		t.Fatalf("Exprs[0] is type %T, want *expr.Objref", rules[0].Exprs[0])
	}
	if want := r.Exprs[0]; !reflect.DeepEqual(objref, want) {
		t.Errorf("objref expr = %+v, wanted %+v", objref, want)
	}
}

func TestObjAPICounterLegacyType(t *testing.T) {
	if os.Getenv("TRAVIS") == "true" {
		t.SkipNow()
	}

	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	tableOther := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "foo",
	})

	chain := c.AddChain(&nftables.Chain{
		Name:     "chain",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityFilter,
	})

	counter1 := c.AddObj(&nftables.CounterObj{
		Table:   table,
		Name:    "fwded1",
		Bytes:   1,
		Packets: 1,
	})

	counter2 := c.AddObj(&nftables.CounterObj{
		Table:   table,
		Name:    "fwded2",
		Bytes:   1,
		Packets: 1,
	})

	c.AddObj(&nftables.CounterObj{
		Table:   tableOther,
		Name:    "fwdedOther",
		Bytes:   0,
		Packets: 0,
	})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Objref{
				Type: 1,
				Name: "fwded1",
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	objs, err := c.GetObjects(table)
	if err != nil {
		t.Errorf("c.GetObjects(table) failed: %v failed", err)
	}

	if got := len(objs); got != 2 {
		t.Fatalf("unexpected number of objects: got %d, want %d", got, 2)
	}

	objsOther, err := c.GetObjects(tableOther)
	if err != nil {
		t.Errorf("c.GetObjects(tableOther) failed: %v failed", err)
	}

	if got := len(objsOther); got != 1 {
		t.Fatalf("unexpected number of objects: got %d, want %d", got, 1)
	}

	obj1, err := c.GetObject(counter1)
	if err != nil {
		t.Errorf("c.GetObject(counter1) failed: %v failed", err)
	}

	rcounter1, ok := obj1.(*nftables.CounterObj)

	if !ok {
		t.Fatalf("unexpected type: got %T, want *nftables.CounterObj", rcounter1)
	}

	if rcounter1.Name != "fwded1" {
		t.Fatalf("unexpected counter name: got %s, want %s", rcounter1.Name, "fwded1")
	}

	obj2, err := c.GetObject(counter2)
	if err != nil {
		t.Errorf("c.GetObject(counter2) failed: %v failed", err)
	}

	rcounter2, ok := obj2.(*nftables.CounterObj)

	if !ok {
		t.Fatalf("unexpected type: got %T, want *nftables.CounterObj", rcounter2)
	}

	if rcounter2.Name != "fwded2" {
		t.Fatalf("unexpected counter name: got %s, want %s", rcounter2.Name, "fwded2")
	}

	_, err = c.ResetObject(counter1)

	if err != nil {
		t.Errorf("c.ResetObjects(table) failed: %v failed", err)
	}

	obj1, err = c.GetObject(counter1)

	if err != nil {
		t.Errorf("c.GetObject(counter1) failed: %v failed", err)
	}

	if counter1 := obj1.(*nftables.CounterObj); counter1.Packets > 0 {
		t.Errorf("unexpected packets number: got %d, want %d", counter1.Packets, 0)
	}

	obj2, err = c.GetObject(counter2)

	if err != nil {
		t.Errorf("c.GetObject(counter2) failed: %v failed", err)
	}

	if counter2 := obj2.(*nftables.CounterObj); counter2.Packets != 1 {
		t.Errorf("unexpected packets number: got %d, want %d", counter2.Packets, 1)
	}

	legacy, err := c.GetObj(counter1)
	if err != nil {
		t.Errorf("c.GetObj(counter1) failed: %v failed", err)
	}

	if len(legacy) != 2 {
		t.Errorf("unexpected number of objects: got %d, want %d", len(legacy), 2)
	}

	legacyReset, err := c.GetObjReset(counter1)
	if err != nil {
		t.Errorf("c.GetObjReset(counter1) failed: %v failed", err)
	}

	if len(legacyReset) != 2 {
		t.Errorf("unexpected number of objects: got %d, want %d", len(legacyReset), 2)
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
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x08\x00\x09\x00\x00\x00\x00\x01\xf0\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x07\x08\x00\x01\x00\x00\x00\x00\x01\x38\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x18\x00\x03\x80\x14\x00\x01\x00\x75\x70\x6c\x69\x6e\x6b\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x0d\x08\x00\x04\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x0c\x00\x04\x80\x05\x00\x01\x00\x02\x00\x00\x00\x0c\x00\x05\x80\x05\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x05\x00\x01\x00\x00\x00\x00\x00\x20\x00\x01\x80\x07\x00\x01\x00\x72\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x01\x00\x00\x00\x00\x01\x40\x00\x01\x80\x0e\x00\x01\x00\x62\x79\x74\x65\x6f\x72\x64\x65\x72\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x04\x00\x00\x00\x00\x02\x08\x00\x05\x00\x00\x00\x00\x02\x3c\x00\x01\x80\x0b\x00\x01\x00\x65\x78\x74\x68\x64\x72\x00\x00\x2c\x00\x02\x80\x08\x00\x07\x00\x00\x00\x00\x01\x05\x00\x02\x00\x02\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x08\x00\x06\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

func TestMatchPacketHeader(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add table ip nat
	//
	// The nft(8) command sequence was adopted from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain filter input '{' type filter hook forward priority filter \; '}'
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0a\x00\x03\x00\x69\x6e\x70\x75\x74\x00\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip filter input tcp flags syn tcp option maxseg size 1-500 drop
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0a\x00\x02\x00\x69\x6e\x70\x75\x74\x00\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\xc4\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x0d\x08\x00\x04\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x0c\x00\x04\x80\x05\x00\x01\x00\x02\x00\x00\x00\x0c\x00\x05\x80\x05\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x05\x00\x01\x00\x00\x00\x00\x00\x44\x00\x01\x80\x0b\x00\x01\x00\x65\x78\x74\x68\x64\x72\x00\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x05\x00\x02\x00\x02\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x08\x00\x06\x00\x00\x00\x00\x01\x08\x00\x05\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x05\x0c\x00\x03\x80\x06\x00\x01\x00\x00\x01\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x03\x0c\x00\x03\x80\x06\x00\x01\x00\x01\xf4\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	input := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
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

			// [ exthdr load tcpopt 2b @ 2 + 2 => reg 1 ]
			&expr.Exthdr{
				DestRegister: 1,
				Type:         2, // TODO
				Offset:       2,
				Len:          2,
				Op:           expr.ExthdrOpTcpopt,
			},

			// [ cmp gte reg 1 0x00000100 ]
			&expr.Cmp{
				Op:       expr.CmpOpGte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(1)),
			},
			// [ cmp lte reg 1 0x0000f401 ]
			&expr.Cmp{
				Op:       expr.CmpOpLte,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(uint16(500)),
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
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x08\x00\x09\x00\x00\x00\x00\x01\xe4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x04\xd2\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x08\x00\x09\x00\x00\x00\x00\x02\xe8\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x30\x00\x01\x80\x0b\x00\x01\x00\x6c\x6f\x6f\x6b\x75\x70\x00\x00\x20\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x01\x00\x5f\x5f\x73\x65\x74\x25\x64\x00\x08\x00\x04\x00\x00\x00\x00\x01\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

func TestCappedErrMsgOnSets(t *testing.T) {
	_, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	c, err := nftables.New(nftables.WithNetNSFd(int(newNS)), nftables.AsLasting())
	if err != nil {
		t.Fatalf("nftables.New() failed: %v", err)
	}
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	if err := c.Flush(); err != nil {
		t.Errorf("failed adding table: %v", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		t.Errorf("failed to list IPv4 tables: %v", err)
	}

	for _, t := range tables {
		if t.Name == "filter" {
			filter = t
			break
		}
	}

	ifSet := &nftables.Set{
		Table:   filter,
		Name:    "if_set",
		KeyType: nftables.TypeIFName,
	}
	if err := c.AddSet(ifSet, nil); err != nil {
		t.Errorf("c.AddSet(ifSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("failed adding set ifSet: %v", err)
	}
	ifSet, err = c.GetSetByName(filter, "if_set")
	if err != nil {
		t.Fatalf("failed getting set by name: %v", err)
	}

	elems, err := c.GetSetElements(ifSet)
	if err != nil {
		t.Errorf("failed getting set elements (ifSet): %v", err)
	}

	if got, want := len(elems), 0; got != want {
		t.Errorf("first GetSetElements(ifSet) call len not equal: got %d, want %d", got, want)
	}

	elements := []nftables.SetElement{
		{Key: []byte("012345678912345\x00")},
	}
	if err := c.SetAddElements(ifSet, elements); err != nil {
		t.Errorf("adding SetElements(ifSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("failed adding set elements ifSet: %v", err)
	}

	elems, err = c.GetSetElements(ifSet)
	if err != nil {
		t.Fatalf("failed getting set elements (ifSet): %v", err)
	}

	if got, want := len(elems), 1; got != want {
		t.Fatalf("second GetSetElements(ifSet) call len not equal: got %d, want %d", got, want)
	}

	if got, want := elems, elements; !reflect.DeepEqual(elems, elements) {
		t.Errorf("SetElements(ifSet) not equal: got %v, want %v", got, want)
	}
}

func TestCreateUseNamedSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "test",
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
	if sets[0].Name != "test" {
		t.Errorf("set[0].Name = %q, want test", sets[0].Name)
	}
	if sets[1].Name != "IPs_4_dayz" {
		t.Errorf("set[1].Name = %q, want IPs_4_dayz", sets[1].Name)
	}
}

func TestCreateAutoMergeSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:     filter,
		Name:      "test",
		KeyType:   nftables.TypeInetService,
		Interval:  true,
		AutoMerge: true,
	}
	if err := c.AddSet(portSet, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.SetAddElements(portSet, []nftables.SetElement{{Key: binaryutil.BigEndian.PutUint16(22)}}); err != nil {
		t.Errorf("c.SetVal(portSet) failed: %v", err)
	}

	ipSet := &nftables.Set{
		Table:     filter,
		Name:      "IPs_4_dayz",
		KeyType:   nftables.TypeIPAddr,
		Interval:  true,
		AutoMerge: true,
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
	if !sets[0].AutoMerge {
		t.Errorf("set[0].AutoMerge = %v, want true", sets[0].AutoMerge)
	}
	if !sets[1].AutoMerge {
		t.Errorf("set[1].AutoMerge = %v, want true", sets[1].AutoMerge)
	}
}

func TestIP6SetAddElements(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "filter",
	})
	portSet := &nftables.Set{
		Table:   filter,
		Name:    "ports",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.SetAddElements(portSet, []nftables.SetElement{
		{Key: binaryutil.BigEndian.PutUint16(22)},
		{Key: binaryutil.BigEndian.PutUint16(80)},
	}); err != nil {
		t.Errorf("c.SetVal(portSet) failed: %v", err)
	}

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	sets, err := c.GetSets(filter)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1", len(sets))
	}

	elements, err := c.GetSetElements(sets[0])
	if err != nil {
		t.Errorf("c.GetSetElements(portSet) failed: %v", err)
	}
	if len(elements) != 2 {
		t.Fatalf("len(portSetElements) = %d, want 2", len(elements))
	}
}

func TestSetElementBatching(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	portSet := &nftables.Set{
		Table:   filter,
		Name:    "ports",
		KeyType: nftables.TypeInetService,
	}
	// The 5000 elements will need to be split into 3 batches to make each batch
	// fit into a message.
	elements := make([]nftables.SetElement, 5000)
	for i := range elements {
		elements[i].Key = binaryutil.BigEndian.PutUint16(uint16(i))
		elements[i].Comment = "0123456789"
	}
	if err := c.AddSet(portSet, elements); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	gotElements, err := c.GetSetElements(portSet)
	if err != nil {
		t.Errorf("c.GetSetElements(portSet) failed: %v", err)
	}
	if len(gotElements) != len(elements) {
		t.Errorf("len(gotElements) = %d, want %d", len(gotElements), len(elements))
	}
	gotNumbers := make([]bool, len(elements))
	for _, element := range gotElements {
		gotNumbers[binaryutil.BigEndian.Uint16(element.Key)] = true
	}
	for i := range gotNumbers {
		if !gotNumbers[i] {
			t.Errorf("Missing element %d", i)
			break
		}
	}
}

func TestCreateUseCounterSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "test",
		KeyType: nftables.TypeInetService,
		Counter: true,
	}
	if err := c.AddSet(portSet, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.SetAddElements(portSet, []nftables.SetElement{{Key: binaryutil.BigEndian.PutUint16(22)}}); err != nil {
		t.Errorf("c.SetVal(portSet) failed: %v", err)
	}

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	sets, err := c.GetSets(filter)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1", len(sets))
	}
	if sets[0].Name != "test" {
		t.Errorf("set[0].Name = %q, want test", sets[0].Name)
	}
}

func TestCreateDeleteNamedSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "test",
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
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "test",
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

func TestFlushNamedSet(t *testing.T) {
	if os.Getenv("TRAVIS") == "true" {
		t.SkipNow()
	}
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "test",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, []nftables.SetElement{{Key: []byte{0, 22}}, {Key: []byte{0, 23}}}); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	c.FlushSet(portSet)

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	elems, err := c.GetSetElements(portSet)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(elems) != 0 {
		t.Fatalf("len(elems) = %d, want 0", len(elems))
	}
}

func TestSetElementsInterval(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "filter",
	})
	portSet := &nftables.Set{
		Table:         filter,
		Name:          "ports",
		KeyType:       nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetService, nftables.TypeIP6Addr),
		Interval:      true,
		Concatenation: true,
	}
	if err := c.AddSet(portSet, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}

	// { 777c:ab4b:85f0:1614:49e5:d29b:aa7b:cc90 . 50000 . 8709:1cb9:163e:9b55:357f:ef64:708a:edcb }
	keyBytes := []byte{119, 124, 171, 75, 133, 240, 22, 20, 73, 229, 210, 155, 170, 123, 204, 144, 195, 80, 0, 0, 135, 9, 28, 185, 22, 62, 155, 85, 53, 127, 239, 100, 112, 138, 237, 203}
	// { 777c:ab4b:85f0:1614:49e5:d29b:aa7b:cc90 . 60000 . 8709:1cb9:163e:9b55:357f:ef64:708a:edcb }
	keyEndBytes := []byte{119, 124, 171, 75, 133, 240, 22, 20, 73, 229, 210, 155, 170, 123, 204, 144, 234, 96, 0, 0, 135, 9, 28, 185, 22, 62, 155, 85, 53, 127, 239, 100, 112, 138, 237, 203}
	// elements = { 777c:ab4b:85f0:1614:49e5:d29b:aa7b:cc90 . 50000-60000 . 8709:1cb9:163e:9b55:357f:ef64:708a:edcb }
	if err := c.SetAddElements(portSet, []nftables.SetElement{
		{Key: keyBytes, KeyEnd: keyEndBytes},
	}); err != nil {
		t.Errorf("c.SetVal(portSet) failed: %v", err)
	}

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	sets, err := c.GetSets(filter)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1", len(sets))
	}

	elements, err := c.GetSetElements(sets[0])
	if err != nil {
		t.Errorf("c.GetSetElements(portSet) failed: %v", err)
	}
	if len(elements) != 1 {
		t.Fatalf("len(portSetElements) = %d, want 1", len(sets))
	}

	element := elements[0]
	if len(element.Key) == 0 {
		t.Fatal("len(portSetElements.Key) = 0")
	}
	if len(element.KeyEnd) == 0 {
		t.Fatal("len(portSetElements.KeyEnd) = 0")
	}
	if !bytes.Equal(element.Key, keyBytes) {
		t.Fatal("element.Key != keyBytes")
	}
	if !bytes.Equal(element.KeyEnd, keyEndBytes) {
		t.Fatal("element.KeyEnd != keyEndBytes")
	}
}

func TestSetSizeConcat(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "filter",
	})

	set := &nftables.Set{
		Name:          "test-set",
		Table:         filter,
		KeyType:       nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetService, nftables.TypeIP6Addr),
		Dynamic:       true,
		Concatenation: true,
		Size:          200,
	}

	if err := c.AddSet(set, nil); err != nil {
		t.Errorf("c.AddSet(set) failed: %v", err)
	}

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	sets, err := c.GetSets(filter)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("len(sets) = %d, want 1", len(sets))
	}
}

func TestCreateListFlowtable(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	flowtable := &nftables.Flowtable{
		Table: filter,
		Name:  "flowtable_test",
	}

	c.AddTable(filter)
	c.AddFlowtable(flowtable)

	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() failed: %v", err)
	}

	flowtables, err := c.ListFlowtables(filter)
	if err != nil {
		t.Fatalf("c.ListFlowtables() failed: %v", err)
	}

	if got, want := len(flowtables), 1; got != want {
		t.Fatalf("flowtable entry length mismatch: got %d, want %d", got, want)
	}
}

func TestCreateListFlowtableWithDevices(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("net.InterfaceByName() failed: %v", err)
	}

	flowtable := &nftables.Flowtable{
		Table:    filter,
		Name:     "flowtable_test",
		Devices:  []string{lo.Name},
		Hooknum:  nftables.FlowtableHookIngress,
		Priority: nftables.FlowtablePriorityRef(5),
	}

	c.AddTable(filter)
	c.AddFlowtable(flowtable)

	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() failed: %v", err)
	}

	flowtables, err := c.ListFlowtables(filter)
	if err != nil {
		t.Fatalf("c.ListFlowtables() failed: %v", err)
	}

	if got, want := len(flowtables), 1; got != want {
		t.Fatalf("flowtable entry length mismatch: got %d, want %d", got, want)
	}

	sysFlowtable := flowtables[0]
	if got, want := sysFlowtable.Table, flowtable.Table; got != want {
		t.Errorf("flowtables table mismatch: got %v, want %v", got, want)
	}

	if got, want := sysFlowtable.Name, flowtable.Name; got != want {
		t.Errorf("flowtables name mismatch: got %s, want %s", got, want)
	}

	if len(sysFlowtable.Devices) != 1 {
		t.Fatalf("expected 1 device in flowtable, got %d", len(sysFlowtable.Devices))
	}

	if got, want := sysFlowtable.Devices, flowtable.Devices; !reflect.DeepEqual(got, want) {
		t.Errorf("flowtables device mismatch: got %v, want %v", got, want)
	}

	if got, want := *sysFlowtable.Hooknum, *flowtable.Hooknum; got != want {
		t.Errorf("flowtables hook mismatch: got %v, want %v", got, want)
	}

	if got, want := *sysFlowtable.Priority, *flowtable.Priority; got != want {
		t.Errorf("flowtables prio mismatch: got %v, want %v", got, want)
	}
}

func TestCreateDeleteFlowtable(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	flowtable := &nftables.Flowtable{
		Table: filter,
		Name:  "flowtable_test",
	}

	c.AddTable(filter)
	c.AddFlowtable(flowtable)
	flowtable.Name = "flowtable_test_to_delete"
	c.AddFlowtable(flowtable)

	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() failed: %v", err)
	}

	flowtables, err := c.ListFlowtables(filter)
	if err != nil {
		t.Fatalf("c.ListFlowtables() failed: %v", err)
	}

	if got, want := len(flowtables), 2; got != want {
		t.Fatalf("flowtable entry length mismatch: got %d, want %d", got, want)
	}

	c.DelFlowtable(flowtable)
	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() failed: %v", err)
	}

	flowtables, err = c.ListFlowtables(filter)
	if err != nil {
		t.Fatalf("c.ListFlowtables() after deletion failed: %v", err)
	}

	if got, want := len(flowtables), 1; got != want {
		t.Errorf("flowtable entry length mismatch: got %d, want %d", got, want)
	}

	if got, removed := flowtables[0].Name, flowtable.Name; got == removed {
		t.Errorf("wrong flowtable entry deleted")
	}
}

func TestOffload(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}

	accept := nftables.ChainPolicyAccept
	forward := &nftables.Chain{
		Name:     "forward",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookForward,
		Policy:   &accept,
	}

	flowtable := &nftables.Flowtable{
		Table: filter,
		Name:  "flowtable_test",
	}

	c.AddTable(filter)
	c.AddChain(forward)
	c.AddFlowtable(flowtable)

	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() failed: %v", err)
	}

	rule := &nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseNetworkHeader,
				Len:           1,
				Offset:        9,
				DestRegister:  1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x06, 0x00, 0x00, 0x00},
			},
			&expr.FlowOffload{
				Name: flowtable.Name,
			},
		},
	}
	c.AddRule(rule)

	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() offload failed: %v", err)
	}

	rules, err := c.GetRule(filter, forward)
	if err != nil {
		t.Fatalf("c.GetRule() failed: %v", err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("rule count mismatch: got %d, want %d", got, want)
	}

	sysRule := rules[0]
	if got, want := sysRule.Exprs, rule.Exprs; !reflect.DeepEqual(got, want) {
		t.Errorf("rule content mismatch: got %v, want %v", got, want)
	}
}

func TestFlushChain(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	forward := c.AddChain(&nftables.Chain{
		Table: filter,
		Name:  "forward",
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
			// [ cmp eq reg 1 0x000010e1 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0xe1, 0x10},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}
	rules, err := c.GetRules(filter, forward)
	if err != nil {
		t.Errorf("c.GetRules() failed: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}

	c.FlushChain(forward)

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	rules, err = c.GetRules(filter, forward)
	if err != nil {
		t.Errorf("c.GetRules() failed: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
}

func TestFlushTable(t *testing.T) {
	if os.Getenv("TRAVIS") == "true" {
		t.SkipNow()
	}
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	nat := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	forward := c.AddChain(&nftables.Chain{
		Table: filter,
		Name:  "forward",
	})

	input := c.AddChain(&nftables.Chain{
		Table: filter,
		Name:  "input",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Table: nat,
		Name:  "prerouting",
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
			// [ cmp eq reg 1 0x000010e1 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0xe1, 0x10},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
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
			// [ cmp eq reg 1 0x0000162e ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x2e, 0x16},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
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
		t.Errorf("c.Flush() failed: %v", err)
	}
	rules, err := c.GetRules(filter, forward)
	if err != nil {
		t.Errorf("c.GetRules() failed: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}
	rules, err = c.GetRules(filter, input)
	if err != nil {
		t.Errorf("c.GetRules() failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}
	rules, err = c.GetRules(nat, prerouting)
	if err != nil {
		t.Errorf("c.GetRules() failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}

	c.FlushTable(filter)

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	rules, err = c.GetRules(filter, forward)
	if err != nil {
		t.Errorf("c.GetRules() failed: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
	rules, err = c.GetRules(filter, input)
	if err != nil {
		t.Errorf("c.GetRules() failed: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
	rules, err = c.GetRules(nat, prerouting)
	if err != nil {
		t.Errorf("c.GetRules() failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}
}

func TestGetLookupExprDestSet(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
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
		Table:    filter,
		Name:     "test",
		IsMap:    true,
		KeyType:  nftables.TypeInetService,
		DataType: nftables.TypeVerdict,
	}
	if err := c.AddSet(set, nil); err != nil {
		t.Errorf("c.AddSet(set) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        set.Name,
				SetID:          set.ID,
				DestRegister:   0,
				IsDestRegSet:   true,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(
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
	if got, want := len(rules[0].Exprs), 4; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	lookup, lookupOk := rules[0].Exprs[3].(*expr.Lookup)
	if !lookupOk {
		t.Fatalf("Exprs[3] is type %T, want *expr.Lookup", rules[0].Exprs[3])
	}
	if want := (&expr.Lookup{
		SourceRegister: 1,
		SetName:        set.Name,
		DestRegister:   0,
		IsDestRegSet:   true,
	}); !reflect.DeepEqual(lookup, want) {
		t.Errorf("lookup expr = %+v, wanted %+v", lookup, want)
	}
}

func TestGetRuleLookupVerdictImmediate(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
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
		Name:    "test",
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
			// [ immediate reg 2 test ]
			&expr.Immediate{
				Register: 2,
				Data:     []byte("test"),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(
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
		Data:     []byte("test"),
	}); !reflect.DeepEqual(imm, want) {
		t.Errorf("verdict expr = %+v, wanted %+v", imm, want)
	}
}

func TestDynset(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
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
		Table:      filter,
		Name:       "dynamic-set",
		KeyType:    nftables.TypeIPAddr,
		HasTimeout: true,
		Timeout:    time.Duration(600 * time.Second),
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
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       uint32(12),
				Len:          uint32(4),
			},
			&expr.Dynset{
				SrcRegKey: 1,
				SetName:   set.Name,
				SetID:     set.ID,
				Operation: uint32(unix.NFT_DYNSET_OP_UPDATE),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(
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
	if got, want := len(rules[0].Exprs), 2; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	dynset, dynsetOk := rules[0].Exprs[1].(*expr.Dynset)
	if !dynsetOk {
		t.Fatalf("Exprs[0] is type %T, want *expr.Dynset", rules[0].Exprs[1])
	}
	if want := (&expr.Dynset{
		SrcRegKey: 1,
		SetName:   set.Name,
		Operation: uint32(unix.NFT_DYNSET_OP_UPDATE),
	}); !reflect.DeepEqual(dynset, want) {
		t.Errorf("dynset expr = %+v, wanted %+v", dynset, want)
	}
}

func TestDynsetWithOneExpression(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()
	table := &nftables.Table{
		Name:   "filter",
		Family: nftables.TableFamilyIPv4,
	}
	chain := &nftables.Chain{
		Name:     "forward",
		Hooknum:  nftables.ChainHookForward,
		Table:    table,
		Priority: nftables.ChainPriorityRef(0),
		Type:     nftables.ChainTypeFilter,
	}
	set := &nftables.Set{
		Table:   table,
		Name:    "myMeter",
		KeyType: nftables.TypeIPAddr,
		Dynamic: true,
	}
	c.AddTable(table)
	c.AddChain(chain)
	if err := c.AddSet(set, nil); err != nil {
		t.Errorf("c.AddSet(myMeter) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       uint32(12),
				Len:          uint32(4),
			},
			&expr.Dynset{
				SrcRegKey: 1,
				SetName:   set.Name,
				Operation: uint32(unix.NFT_DYNSET_OP_ADD),
				Exprs: []expr.Any{
					&expr.Limit{
						Type:  expr.LimitTypePkts,
						Rate:  200,
						Unit:  expr.LimitTimeSecond,
						Burst: 5,
					},
				},
			},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}
	c.AddRule(rule)
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}
	if got, want := len(rules[0].Exprs), 3; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	dynset, dynsetOk := rules[0].Exprs[1].(*expr.Dynset)
	if !dynsetOk {
		t.Fatalf("Exprs[0] is type %T, want *expr.Dynset", rules[0].Exprs[1])
	}

	if got, want := len(dynset.Exprs), 1; got != want {
		t.Fatalf("unexpected number of dynset.Exprs: got %d, want %d", got, want)
	}

	if got, want := dynset.SetName, set.Name; got != want {
		t.Fatalf("dynset.SetName is %s, want %s", got, want)
	}

	if want := (&expr.Limit{
		Type:  expr.LimitTypePkts,
		Rate:  200,
		Unit:  expr.LimitTimeSecond,
		Burst: 5,
	}); !reflect.DeepEqual(dynset.Exprs[0], want) {
		t.Errorf("dynset.Exprs[0] expr = %+v, wanted %+v", dynset.Exprs[0], want)
	}
}

func TestDynsetWithMultipleExpressions(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()
	table := &nftables.Table{
		Name:   "filter",
		Family: nftables.TableFamilyIPv4,
	}
	chain := &nftables.Chain{
		Name:     "forward",
		Hooknum:  nftables.ChainHookForward,
		Table:    table,
		Priority: nftables.ChainPriorityRef(0),
		Type:     nftables.ChainTypeFilter,
	}
	set := &nftables.Set{
		Table:   table,
		Name:    "myMeter",
		KeyType: nftables.TypeIPAddr,
		Dynamic: true,
	}
	c.AddTable(table)
	c.AddChain(chain)
	if err := c.AddSet(set, nil); err != nil {
		t.Errorf("c.AddSet(myMeter) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       uint32(12),
				Len:          uint32(4),
			},
			&expr.Dynset{
				SrcRegKey: 1,
				SetName:   set.Name,
				Operation: uint32(unix.NFT_DYNSET_OP_ADD),
				Exprs: []expr.Any{
					&expr.Connlimit{
						Count: 20,
						Flags: 1,
					},
					&expr.Limit{
						Type:  expr.LimitTypePkts,
						Rate:  10,
						Unit:  expr.LimitTimeSecond,
						Burst: 2,
					},
				},
			},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}
	c.AddRule(rule)
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}
	if got, want := len(rules[0].Exprs), 3; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	dynset, dynsetOk := rules[0].Exprs[1].(*expr.Dynset)
	if !dynsetOk {
		t.Fatalf("Exprs[0] is type %T, want *expr.Dynset", rules[0].Exprs[1])
	}

	if got, want := len(dynset.Exprs), 2; got != want {
		t.Fatalf("unexpected number of dynset.Exprs: got %d, want %d", got, want)
	}

	if got, want := dynset.SetName, set.Name; got != want {
		t.Fatalf("dynset.SetName is %s, want %s", got, want)
	}

	if want := (&expr.Connlimit{
		Count: 20,
		Flags: 1,
	}); !reflect.DeepEqual(dynset.Exprs[0], want) {
		t.Errorf("dynset.Exprs[0] expr = %+v, wanted %+v", dynset.Exprs[0], want)
	}

	if want := (&expr.Limit{
		Type:  expr.LimitTypePkts,
		Rate:  10,
		Unit:  expr.LimitTimeSecond,
		Burst: 2,
	}); !reflect.DeepEqual(dynset.Exprs[1], want) {
		t.Errorf("dynset.Exprs[1] expr = %+v, wanted %+v", dynset.Exprs[1], want)
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
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\xfc\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x00\x16\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x06\x00\x01\x00\x08\xae\x00\x00\x1c\x00\x01\x80\x0a\x00\x01\x00\x72\x65\x64\x69\x72\x00\x00\x00\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x24\x01\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x05\x0c\x00\x03\x80\x06\x00\x01\x00\x00\x01\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x03\x0c\x00\x03\x80\x06\x00\x01\x00\xff\xff\x00\x00\x44\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x30\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x24\x00\x02\x80\x20\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfd\x13\x00\x02\x00\x69\x73\x74\x69\x6f\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
		[]byte("\x02\x00\x00\x00\x08\x00\x01\x00\x6e\x61\x74\x00\x0f\x00\x02\x00\x70\x72\x65\x72\x6f\x75\x74\x69\x6e\x67\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x84\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x0b\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x39\x05\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x08\x00\x09\x00\x00\x00\x00\x01\xf4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x02\x3c\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x06\x00\x01\x00\x07\xe8\x00\x00\x0c\x00\x04\x80\x06\x00\x01\x00\x07\xee\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x08\x00\x09\x00\x00\x00\x00\x01\xa4\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x3c\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x08\x00\x01\x00\xc0\xa8\x01\x00\x0c\x00\x04\x80\x08\x00\x01\x00\xc0\xa8\x02\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
		[]byte("\x0a\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x08\x00\x09\x00\x00\x00\x00\x01\xbc\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x08\x08\x00\x04\x00\x00\x00\x00\x10\x54\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x44\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x18\x00\x03\x80\x14\x00\x01\x00\x20\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x18\x00\x04\x80\x14\x00\x01\x00\x20\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x32\x00\x08\x00\x09\x00\x00\x00\x00\x01\xbc\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x04\x00\x00\x00\x00\x02\x34\x00\x01\x80\x0b\x00\x01\x00\x6c\x6f\x6f\x6b\x75\x70\x00\x00\x24\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01\x0d\x00\x01\x00\x74\x65\x73\x74\x2d\x73\x65\x74\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01"),

		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
		ID:        uint32(1), // rand.Intn(0xffff)),
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

func TestSetComment(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table inet filter
		[]byte("\x01\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add set inet filter setname { type ipv4_addr\; comment \"test comment\" \; }
		[]byte("\x01\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x73\x65\x74\x6e\x61\x6d\x65\x00\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x07\x08\x00\x05\x00\x00\x00\x00\x04\x08\x00\x0a\x00\x00\x00\x00\x02\x13\x00\x0d\x00\x07\x0d\x74\x65\x73\x74\x20\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})

	if err := c.AddSet(&nftables.Set{
		ID:      2,
		Table:   filter,
		Name:    "setname",
		KeyType: nftables.TypeIPAddr,
		Comment: "test comment",
	}, nil); err != nil {
		t.Fatal(err)
	}

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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x78\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x14\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x04\x00\x02\x80"),
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x80\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x1c\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x1c"),
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\xac\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x04\x00\x00\x00\x1c\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x0c\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01"),
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\xe0\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x04\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x04\x00\x00\x00\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x08\x00\x01\x00\x07\xfc\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x61\x73\x71\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x02"),
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
		c, err := nftables.New(expectMessages(t, tt.want))
		if err != nil {
			t.Fatal(err)
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00"),
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x05\x00\x02\x00\x01\x00\x00\x00"),
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			rejectExprs: []expr.Any{
				&expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: unix.NFT_REJECT_ICMP_UNREACH},
			},
		},
	}

	for _, tt := range tests {
		c, err := nftables.New(expectMessages(t, tt.want))
		if err != nil {
			t.Fatal(err)
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x2c\x00\x04\x80\x28\x00\x01\x80\x08\x00\x01\x00\x66\x69\x62\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x03"),
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x2c\x00\x04\x80\x28\x00\x01\x80\x08\x00\x01\x00\x66\x69\x62\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x03"),
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
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x2c\x00\x04\x80\x28\x00\x01\x80\x08\x00\x01\x00\x66\x69\x62\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x09\x08\x00\x02\x00\x00\x00\x00\x01"),
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
		c, err := nftables.New(expectMessages(t, tt.want))
		if err != nil {
			t.Fatal(err)
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

func TestFibSystem(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	chain := c.AddChain(&nftables.Chain{
		Name:  "test-chain",
		Table: filter,
	})

	expect := &expr.Fib{
		Register:       1,
		FlagDADDR:      true,
		ResultADDRTYPE: true,
	}

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: chain,
		Exprs: []expr.Any{expect},
	})

	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() failed with error %+v", err)
	}

	rules, err := c.GetRules(filter, chain)
	if err != nil {
		t.Fatalf("GetRules failed: %v", err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}

	if got, want := len(rules[0].Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	fib := rules[0].Exprs[0].(*expr.Fib)
	if got, want := fib.FlagDADDR, expect.FlagDADDR; got != want {
		t.Errorf("fib daddr not equal: got %+v, want %+v", got, want)
	}

	if got, want := fib.ResultADDRTYPE, expect.ResultADDRTYPE; got != want {
		t.Errorf("fib addr type not equal: got %+v, want %+v", got, want)
	}
}

func TestNumgen(t *testing.T) {
	tests := []struct {
		name        string
		chain       *nftables.Chain
		want        [][]byte
		numgenExprs []expr.Any
	}{
		{
			name: "numgen random",
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
				// nft add rule ip filter base-chain numgen random mod 1  offset 0 vmap { 0 : drop }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x38\x00\x04\x80\x34\x00\x01\x80\x0b\x00\x01\x00\x6e\x75\x6d\x67\x65\x6e\x00\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x04\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			numgenExprs: []expr.Any{
				&expr.Numgen{
					Register: 1,
					Type:     unix.NFT_NG_RANDOM,
					Modulus:  0x1,
					Offset:   0,
				},
			},
		},
		{
			name: "numgen incremental",
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
				// nft add rule ip filter base-chain numgen inc mod 1  offset 0 vmap { 0 : drop }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x38\x00\x04\x80\x34\x00\x01\x80\x0b\x00\x01\x00\x6e\x75\x6d\x67\x65\x6e\x00\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			numgenExprs: []expr.Any{
				&expr.Numgen{
					Register: 1,
					Type:     unix.NFT_NG_INCREMENTAL,
					Modulus:  0x1,
					Offset:   0,
				},
			},
		},
	}

	for _, tt := range tests {
		c, err := nftables.New(expectMessages(t, tt.want))
		if err != nil {
			t.Fatal(err)
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
			Exprs: tt.numgenExprs,
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
		c, err := nftables.New(expectMessages(t, tt.want))
		if err != nil {
			t.Fatal(err)
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
		c, err := nftables.New(expectMessages(t, tt.want))
		if err != nil {
			t.Fatal(err)
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
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\xa8\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x4c\x00\x01\x80\x09\x00\x01\x00\x68\x61\x73\x68\x00\x00\x00\x00\x3c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x04\x08\x00\x04\x00\x00\x00\x00\x02\x08\x00\x05\x00\xfe\xed\xca\xfe\x08\x00\x06\x00\x00\x00\x00\x01\x08\x00\x07\x00\x00\x00\x00\x00\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x03\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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

func TestDup(t *testing.T) {
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

		// nft add table ip mangle
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),

		// nft add chain ip mangle base-chain { type filter hook prerouting priority 0 \; }
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),

		// nft add rule mangle base-chain dup to 127.0.0.50 device lo
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x7c\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x7f\x00\x00\x32\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x08\x00\x01\x00\x01\x00\x00\x00\x20\x00\x01\x80\x08\x00\x01\x00\x64\x75\x70\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02"),

		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.FlushRuleset()

	mangle := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "mangle",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Name:     "base-chain",
		Table:    mangle,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Table: mangle,
		Chain: prerouting,
		Exprs: []expr.Any{
			// [ immediate reg 1 0x3200007f ]
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("127.0.0.50").To4(),
			},
			// [ immediate reg 2 0x00000001 ]
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.NativeEndian.PutUint32(uint32(lo.Index)),
			},
			// [ dup sreg_addr 1 sreg_dev 2 ]
			&expr.Dup{
				RegAddr:     1,
				RegDev:      2,
				IsRegDevSet: true,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestDupWoDev(t *testing.T) {
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

		// nft add table ip mangle
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),

		// nft add chain ip mangle base-chain { type filter hook prerouting priority 0 \; }
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),

		// nft add rule mangle base-chain dup to 127.0.0.50
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x48\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x7f\x00\x00\x32\x18\x00\x01\x80\x08\x00\x01\x00\x64\x75\x70\x00\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),

		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.FlushRuleset()

	mangle := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "mangle",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Name:     "base-chain",
		Table:    mangle,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: mangle,
		Chain: prerouting,
		Exprs: []expr.Any{
			// [ immediate reg 1 0x3200007f ]
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("127.0.0.50").To4(),
			},
			// [ dup sreg_addr 1 sreg_dev 2 ]
			&expr.Dup{
				RegAddr:     1,
				IsRegDevSet: false,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestNotrack(t *testing.T) {
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
		// nft add rule filter base_chain notrack
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x14\x00\x04\x80\x10\x00\x01\x80\x0c\x00\x01\x00\x6e\x6f\x74\x72\x61\x63\x6b\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	nftest.MatchRulesetBytes(t,
		func(c *nftables.Conn) {
			filter := c.AddTable(&nftables.Table{
				Family: nftables.TableFamilyIPv4,
				Name:   "filter",
			})

			prerouting := c.AddChain(&nftables.Chain{
				Name:     "base-chain",
				Table:    filter,
				Type:     nftables.ChainTypeFilter,
				Hooknum:  nftables.ChainHookPrerouting,
				Priority: nftables.ChainPriorityFilter,
			})

			c.AddRule(&nftables.Rule{
				Table: filter,
				Chain: prerouting,
				Exprs: []expr.Any{
					// [ notrack ]
					&expr.Notrack{},
				},
			})
		},
		want)
}

func TestQuota(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip filter regular-chain
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x12\x00\x03\x00\x72\x65\x67\x75\x6c\x61\x72\x2d\x63\x68\x61\x69\x6e\x00\x00\x00"),
		// nft add rule ip filter regular-chain quota over 6 bytes
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x12\x00\x02\x00\x72\x65\x67\x75\x6c\x61\x72\x2d\x63\x68\x61\x69\x6e\x00\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x38\x00\x04\x80\x34\x00\x01\x80\x0a\x00\x01\x00\x71\x75\x6f\x74\x61\x00\x00\x00\x24\x00\x02\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x06\x0c\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
	}

	c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	output := c.AddChain(&nftables.Chain{
		Name:  "regular-chain",
		Table: filter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: output,
		Exprs: []expr.Any{
			// [ quota bytes 6 consumed 0 flags 1 ]
			&expr.Quota{
				Bytes:    6,
				Consumed: 0,
				Over:     true,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestStatelessNAT(t *testing.T) {
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
		// nft add rule ip filter base-chain ip daddr set 192.168.1.1 notrack
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x08\x00\x09\x00\x00\x00\x00\x01\x8c\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\xc0\xa8\x01\x01\x4c\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x3c\x00\x02\x80\x08\x00\x05\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x10\x08\x00\x04\x00\x00\x00\x00\x04\x08\x00\x06\x00\x00\x00\x00\x01\x08\x00\x07\x00\x00\x00\x00\x0a\x08\x00\x08\x00\x00\x00\x00\x01\x10\x00\x01\x80\x0c\x00\x01\x00\x6e\x6f\x74\x72\x61\x63\x6b\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c, err := nftables.New(expectMessages(t, want))
	if err != nil {
		t.Fatal(err)
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
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("192.168.1.1").To4(),
			},
			// [ payload write reg 1 => 4b @ network header + 16 csum_type 1 csum_off 10 csum_flags 0x1 ]
			&expr.Payload{
				OperationType:  expr.PayloadWrite,
				SourceRegister: 1,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         16,
				Len:            4,
				CsumType:       expr.CsumTypeInet,
				CsumOffset:     10,
				CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
			},
			// [ notrack ]
			&expr.Notrack{},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestGetRulesObjref(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	chain := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	counterName := "fwded1"
	c.AddObj(&nftables.CounterObj{
		Table:   table,
		Name:    counterName,
		Bytes:   1,
		Packets: 1,
	})

	counterRule := c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Objref{
				Type: 1,
				Name: counterName,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}
	if got, want := len(rules[0].Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}
	objref, objrefOk := rules[0].Exprs[0].(*expr.Objref)
	if !objrefOk {
		t.Fatalf("Exprs[0] is type %T, want *expr.Objref", rules[0].Exprs[0])
	}
	if want := counterRule.Exprs[0]; !reflect.DeepEqual(objref, want) {
		t.Errorf("objref expr = %+v, wanted %+v", objref, want)
	}
}

func TestAddLimitObj(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "limit_demo",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter",
		Table: table,
	}
	conn.AddChain(c)

	l := &expr.Limit{
		Type:  expr.LimitTypePkts,
		Rate:  400,
		Unit:  expr.LimitTimeMinute,
		Burst: 5,
		Over:  false,
	}
	o := &nftables.NamedObj{
		Table: tr,
		Name:  "limit_test",
		Type:  nftables.ObjTypeLimit,
		Obj:   l,
	}
	conn.AddObj(o)

	if err := conn.Flush(); err != nil {
		t.Errorf("conn.Flush() failed: %v", err)
	}

	obj, err := conn.GetObj(&nftables.NamedObj{
		Table: table,
		Name:  "limit_test",
		Type:  nftables.ObjTypeLimit,
	})
	if err != nil {
		t.Fatalf("conn.GetObj() failed: %v", err)
	}

	if got, want := len(obj), 1; got != want {
		t.Fatalf("unexpected object list length: got %d, want %d", got, want)
	}

	o1, ok := obj[0].(*nftables.NamedObj)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *ObjAttr", obj[0])
	}
	if got, want := o1.Name, o.Name; got != want {
		t.Fatalf("limit name mismatch: got %s, want %s", got, want)
	}
	q, ok := o1.Obj.(*expr.Limit)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *expr.Quota", o1.Obj)
	}
	if got, want := q.Burst, l.Burst; got != want {
		t.Fatalf("limit burst mismatch: got %d, want %d", got, want)
	}
	if got, want := q.Unit, l.Unit; got != want {
		t.Fatalf("limit unit mismatch: got %d, want %d", got, want)
	}
	if got, want := q.Rate, l.Rate; got != want {
		t.Fatalf("limit rate mismatch: got %v, want %v", got, want)
	}
	if got, want := q.Over, l.Over; got != want {
		t.Fatalf("limit over mismatch: got %v, want %v", got, want)
	}
	if got, want := q.Type, l.Type; got != want {
		t.Fatalf("limit type mismatch: got %v, want %v", got, want)
	}
}

func TestAddQuotaObj(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "quota_demo",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter",
		Table: table,
	}
	conn.AddChain(c)

	o := &nftables.NamedObj{
		Table: tr,
		Name:  "q_test",
		Type:  nftables.ObjTypeQuota,
		Obj: &expr.Quota{
			Bytes:    0x06400000,
			Consumed: 0,
			Over:     true,
		},
	}
	conn.AddObj(o)

	if err := conn.Flush(); err != nil {
		t.Fatalf("conn.Flush() failed: %v", err)
	}

	obj, err := conn.GetObj(&nftables.NamedObj{
		Table: table,
		Name:  "q_test",
		Type:  nftables.ObjTypeQuota,
	})
	if err != nil {
		t.Fatalf("conn.GetObj() failed: %v", err)
	}

	if got, want := len(obj), 1; got != want {
		t.Fatalf("unexpected object list length: got %d, want %d", got, want)
	}

	o1, ok := obj[0].(*nftables.NamedObj)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *ObjAttr", obj[0])
	}
	if got, want := o1.Name, o.Name; got != want {
		t.Fatalf("quota name mismatch: got %s, want %s", got, want)
	}
	q, ok := o1.Obj.(*expr.Quota)
	if !ok {
		t.Fatalf("unexpected type: got %T, want *expr.Quota", o1.Obj)
	}
	o2, _ := o.Obj.(*expr.Quota)
	if got, want := q.Bytes, o2.Bytes; got != want {
		t.Fatalf("quota bytes mismatch: got %d, want %d", got, want)
	}
	if got, want := q.Consumed, o2.Consumed; got != want {
		t.Fatalf("quota consumed mismatch: got %d, want %d", got, want)
	}
	if got, want := q.Over, o2.Over; got != want {
		t.Fatalf("quota over mismatch: got %v, want %v", got, want)
	}
}

func TestAddQuotaObjRef(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "quota_demo",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter",
		Table: table,
	}
	conn.AddChain(c)

	o := &nftables.QuotaObj{
		Table:    tr,
		Name:     "q_test",
		Bytes:    0x06400000,
		Consumed: 0,
		Over:     true,
	}
	conn.AddObj(o)

	r := &nftables.Rule{
		Table: table,
		Chain: c,
		Exprs: []expr.Any{
			&expr.Objref{
				Type: 2,
				Name: "q_test",
			},
		},
	}
	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		t.Fatalf("failed to flush: %v", err)
	}

	rules, err := conn.GetRules(table, c)
	if err != nil {
		t.Fatalf("failed to get rules: %v", err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}
	if got, want := len(rules[0].Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	objref, ok := rules[0].Exprs[0].(*expr.Objref)
	if !ok {
		t.Fatalf("Exprs[0] is type %T, want *expr.Objref", rules[0].Exprs[0])
	}
	if want := r.Exprs[0]; !reflect.DeepEqual(objref, want) {
		t.Errorf("objref expr = %+v, wanted %+v", objref, want)
	}
}

func TestDeleteQuotaObjMixedTypes(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := &nftables.Table{
		Name:   "quota_demo",
		Family: nftables.TableFamilyIPv4,
	}
	tr := conn.AddTable(table)

	c := &nftables.Chain{
		Name:  "filter",
		Table: table,
	}
	conn.AddChain(c)

	o := &nftables.NamedObj{
		Table: tr,
		Name:  "q_test",
		Type:  nftables.ObjTypeQuota,
		Obj: &expr.Quota{
			Bytes:    0x06400000,
			Consumed: 0,
			Over:     true,
		},
	}
	conn.AddObj(o)

	if err := conn.Flush(); err != nil {
		t.Fatalf("conn.Flush() failed: %v", err)
	}

	obj, err := conn.GetObj(&nftables.NamedObj{
		Table: tr,
		Name:  "q_test",
		Type:  nftables.ObjTypeQuota,
	})
	if err != nil {
		t.Fatalf("conn.GetObj() failed: %v", err)
	}

	if got, want := len(obj), 1; got != want {
		t.Fatalf("unexpected number of objects: got %d, want %d", got, want)
	}

	o2, _ := o.Obj.(*expr.Quota)
	want := &nftables.NamedObj{
		Table: tr,
		Name:  "q_test",
		Type:  nftables.ObjTypeQuota,
		Obj: &expr.Quota{
			Bytes:    o2.Bytes,
			Consumed: o2.Consumed,
			Over:     o2.Over,
		},
	}
	if got, want := obj[0], want; !reflect.DeepEqual(got, want) {
		t.Errorf("got = %+v, want = %+v", got, want)
	}

	conn.DeleteObject(&nftables.QuotaObj{
		Table: tr,
		Name:  "q_test",
	})

	if err := conn.Flush(); err != nil {
		t.Fatalf("conn.Flush() failed: %v", err)
	}

	obj, err = conn.GetObj(&nftables.QuotaObj{
		Table: table,
		Name:  "q_test",
	})
	if err != nil {
		t.Fatalf("conn.GetObj() failed: %v", err)
	}
	if got, want := len(obj), 0; got != want {
		t.Fatalf("unexpected object list length: got %d, want %d", got, want)
	}
}

func TestGetRulesQueue(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	chain := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	queueRule := c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Queue{
				Num:  1000,
				Flag: expr.QueueFlagBypass,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}
	if got, want := len(rules[0].Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}
	queueExpr, ok := rules[0].Exprs[0].(*expr.Queue)
	if !ok {
		t.Fatalf("Exprs[0] is type %T, want *expr.Queue", rules[0].Exprs[0])
	}
	if want := queueRule.Exprs[0]; !reflect.DeepEqual(queueExpr, want) {
		t.Errorf("queue expr = %+v, wanted %+v", queueExpr, want)
	}
}

func TestNftablesCompat(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	input := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	// -tcp --dport 0:65534 --sport 0:65534
	tcpMatch := &expr.Match{
		Name: "tcp",
		Info: &xt.Tcp{
			SrcPorts: [2]uint16{0, 65534},
			DstPorts: [2]uint16{0, 65534},
		},
	}

	// -udp --dport 0:65534 --sport 0:65534
	udpMatch := &expr.Match{
		Name: "udp",
		Info: &xt.Udp{
			SrcPorts: [2]uint16{0, 65534},
			DstPorts: [2]uint16{0, 65534},
		},
	}

	// - j TCPMSS --set-mss 1460
	mess := xt.Unknown([]byte{1460 & 0xff, (1460 >> 8) & 0xff})
	tcpMessTarget := &expr.Target{
		Name: "TCPMSS",
		Info: &mess,
	}

	// -m state --state ESTABLISHED
	ctMatch := &expr.Match{
		Name: "conntrack",
		Rev:  1,
		Info: &xt.ConntrackMtinfo1{
			ConntrackMtinfoBase: xt.ConntrackMtinfoBase{
				MatchFlags: 0x2001,
			},
			StateMask: 0x02,
		},
	}

	// -p tcp --dport --dport 0:65534 --sport 0:65534 -m state --state ESTABLISHED -j TCPMSS --set-mss 1460
	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			tcpMatch,
			ctMatch,
			tcpMessTarget,
		},
	})
	if err := c.Flush(); err != nil {
		t.Fatalf("add rule fail %#v", err)
	}

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			udpMatch,
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	if err := c.Flush(); err != nil {
		t.Fatalf("add rule %#v fail", err)
	}

	// -m state --state ESTABLISHED -j ACCEPT
	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			ctMatch,
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	if err := c.Flush(); err != nil {
		t.Fatalf("add rule %#v fail", err)
	}

	// -p udp --dport --dport 0:65534 --sport 0:65534 -m state --state ESTABLISHED -j ACCEPT
	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			tcpMatch,
			udpMatch,
			ctMatch,
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	if err := c.Flush(); err == nil {
		t.Fatalf("compat policy should conflict and err should not be err")
	}
}

func TestNftablesDeadlock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		readBufSize  int
		writeBufSize int
		sendRules    int
		wantRules    int
		wantErr      error
	}{
		{
			name:         "recv",
			readBufSize:  1024,
			writeBufSize: 1 * 1024 * 1024,
			sendRules:    2048,
			wantRules:    2048,
			wantErr:      syscall.ENOBUFS,
		},
		{
			name:         "send",
			readBufSize:  1 * 1024 * 1024,
			writeBufSize: 1024,
			sendRules:    2048,
			wantRules:    0,
			wantErr:      syscall.EMSGSIZE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, newNS := nftest.OpenSystemConn(t, *enableSysTests)
			conn, err := nftables.New(nftables.WithNetNSFd(int(newNS)), nftables.WithSockOptions(func(conn *netlink.Conn) error {
				if err := conn.SetWriteBuffer(tt.writeBufSize); err != nil {
					return err
				}
				if err := conn.SetReadBuffer(tt.readBufSize); err != nil {
					return err
				}
				return nil
			}))
			if err != nil {
				t.Fatalf("nftables.New() failed: %v", err)
			}
			defer nftest.CleanupSystemConn(t, newNS)
			conn.FlushRuleset()
			defer conn.FlushRuleset()

			table := conn.AddTable(&nftables.Table{
				Name:   "test_deadlock",
				Family: nftables.TableFamilyIPv4,
			})

			chain := conn.AddChain(&nftables.Chain{
				Name:  "filter",
				Table: table,
			})

			for i := 0; i < tt.sendRules; i++ {
				conn.AddRule(&nftables.Rule{
					Table: table,
					Chain: chain,
					Exprs: []expr.Any{
						&expr.Verdict{
							Kind: expr.VerdictAccept,
						},
					},
				})
			}

			flushErr := conn.Flush()
			rules, err := conn.GetRules(table, chain)
			if err != nil {
				t.Fatalf("conn.GetRules() failed: %v", err)
			}

			if !errors.Is(flushErr, tt.wantErr) {
				t.Errorf("conn.Flush() failed: %v", flushErr)
			}

			if got, want := len(rules), tt.wantRules; got != want {
				t.Fatalf("got rules %d, want rules %d", got, want)
			}
		})
	}
}
func TestSetElementComment(t *testing.T) {
	// Create a new network namespace to test these operations
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	// Add a new table
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}
	conn.AddTable(table)

	// Create a new set
	set := &nftables.Set{
		Name:    "test-set",
		Table:   table,
		KeyType: nftables.TypeIPAddr,
	}

	// Create set elements with comments
	elements := []nftables.SetElement{
		{
			Key:     net.ParseIP("192.0.2.1").To4(),
			Comment: "First IP address",
		},
		{
			Key:     net.ParseIP("192.0.2.2").To4(),
			Comment: "Second IP address",
		},
	}

	// Add the set with elements
	if err := conn.AddSet(set, elements); err != nil {
		t.Fatalf("failed to add set: %v", err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatalf("failed to flush: %v", err)
	}

	// Get the set elements back and verify comments
	gotElements, err := conn.GetSetElements(set)
	if err != nil {
		t.Fatalf("failed to get set elements: %v", err)
	}

	if got, want := len(gotElements), len(elements); got != want {
		t.Fatalf("got %d elements, want %d", got, want)
	}

	// Create maps to compare elements by their IP addresses
	wantMap := make(map[string]string)
	for _, elem := range elements {
		wantMap[string(elem.Key)] = elem.Comment
	}

	gotMap := make(map[string]string)
	for _, elem := range gotElements {
		gotMap[string(elem.Key)] = elem.Comment
	}

	// Compare the comments for each IP
	for ip, wantComment := range wantMap {
		if gotComment, ok := gotMap[ip]; !ok {
			t.Errorf("IP %s not found in retrieved elements", ip)
		} else if gotComment != wantComment {
			t.Errorf("for IP %s: got comment %q, want comment %q", ip, gotComment, wantComment)
		}
	}
}

func TestAutoBufferSize(t *testing.T) {
	conn, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	conn.FlushRuleset()
	defer conn.FlushRuleset()

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "test-table",
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:  "test-chain",
		Table: table,
	})

	for range 4096 {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		})
	}

	if err := conn.Flush(); err != nil {
		t.Fatalf("failed to flush: %v", err)
	}
}
