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

// Package nftables manipulates Linux nftables (the iptables successor).
package nftables

import (
	"fmt"
	"math"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func extraHeader(family uint8, resID uint16) []byte {
	return append([]byte{
		family,
		unix.NFNETLINK_V0,
	}, binaryutil.NativeEndian.PutUint16(resID)...)
}

func batch(messages []netlink.Message) []netlink.Message {
	batch := []netlink.Message{
		{
			Header: netlink.Header{
				Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_BEGIN),
				Flags: netlink.HeaderFlagsRequest,
			},
			Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
		},
	}

	batch = append(batch, messages...)

	batch = append(batch, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_END),
			Flags: netlink.HeaderFlagsRequest,
		},
		Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
	})

	return batch
}

// ChainHook specifies at which step in packet processing the Chain should be
// executed. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_hooks
type ChainHook uint32

// Possible ChainHook values.
const (
	ChainHookPrerouting  ChainHook = unix.NF_INET_PRE_ROUTING
	ChainHookInput       ChainHook = unix.NF_INET_LOCAL_IN
	ChainHookForward     ChainHook = unix.NF_INET_FORWARD
	ChainHookOutput      ChainHook = unix.NF_INET_LOCAL_OUT
	ChainHookPostrouting ChainHook = unix.NF_INET_POST_ROUTING
	ChainHookIngress     ChainHook = unix.NF_NETDEV_INGRESS
)

// ChainPriority orders the chain relative to Netfilter internal operations. See
// also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_priority
type ChainPriority int32

// Possible ChainPriority values.
const ( // from /usr/include/linux/netfilter_ipv4.h
	ChainPriorityFirst            ChainPriority = math.MinInt32
	ChainPriorityConntrackDefrag  ChainPriority = -400
	ChainPriorityRaw              ChainPriority = -300
	ChainPrioritySELinuxFirst     ChainPriority = -225
	ChainPriorityConntrack        ChainPriority = -200
	ChainPriorityMangle           ChainPriority = -150
	ChainPriorityNATDest          ChainPriority = -100
	ChainPriorityFilter           ChainPriority = 0
	ChainPrioritySecurity         ChainPriority = 50
	ChainPriorityNATSource        ChainPriority = 100
	ChainPrioritySELinuxLast      ChainPriority = 225
	ChainPriorityConntrackHelper  ChainPriority = 300
	ChainPriorityConntrackConfirm ChainPriority = math.MaxInt32
	ChainPriorityLast             ChainPriority = math.MaxInt32
)

// ChainType defines what this chain will be used for. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Base_chain_types
type ChainType string

// Possible ChainType values.
const (
	ChainTypeFilter ChainType = "filter"
	ChainTypeRoute  ChainType = "route"
	ChainTypeNAT    ChainType = "nat"
)

// A Chain contains Rules. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains
type Chain struct {
	Name     string
	Table    *Table
	Hooknum  ChainHook
	Priority ChainPriority
	Type     ChainType
}

// AddChain adds the specified Chain. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_base_chains
func (cc *Conn) AddChain(c *Chain) *Chain {
	chainHook := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_HOOK_HOOKNUM, Data: binaryutil.BigEndian.PutUint32(uint32(c.Hooknum))},
		{Type: unix.NFTA_HOOK_PRIORITY, Data: binaryutil.BigEndian.PutUint32(uint32(c.Priority))},
	})

	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(c.Table.Name + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(c.Name + "\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_CHAIN_HOOK, Data: chainHook},
		{Type: unix.NFTA_CHAIN_TYPE, Data: []byte(c.Type + "\x00")},
	})

	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWCHAIN),
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge | netlink.HeaderFlagsCreate,
		},
		Data: append(extraHeader(unix.AF_INET, 0), data...),
	})

	return c
}

func (cc *Conn) setErr(err error) {
	if cc.err != nil {
		return
	}
	cc.err = err
}

func (cc *Conn) marshalAttr(attrs []netlink.Attribute) []byte {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		cc.setErr(err)
		return nil
	}
	return b
}

func (cc *Conn) marshalExpr(e expr.Any) []byte {
	b, err := expr.Marshal(e)
	if err != nil {
		cc.setErr(err)
		return nil
	}
	return b
}

// A Rule does something with a packet. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management
type Rule struct {
	Table *Table
	Chain *Chain
	Exprs []expr.Any
}

// AddRule adds the specified Rule. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management
func (cc *Conn) AddRule(r *Rule) *Rule {
	exprAttrs := make([]netlink.Attribute, len(r.Exprs))
	for idx, expr := range r.Exprs {
		exprAttrs[idx] = netlink.Attribute{
			Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM,
			Data: cc.marshalExpr(expr),
		}
	}

	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(r.Table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(r.Chain.Name + "\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: cc.marshalAttr(exprAttrs)},
	})

	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWRULE),
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge | netlink.HeaderFlagsCreate,
		},
		Data: append(extraHeader(unix.AF_INET, 0), data...),
	})

	return r
}

// TableFamily specifies the address family for this table.
type TableFamily byte

// Possible TableFamily values.
const (
	TableFamilyIPv4 TableFamily = unix.AF_INET
	TableFamilyIPv6 TableFamily = unix.AF_INET6
)

// A Table contains Chains. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_tables
type Table struct {
	Name   string
	Family TableFamily
}

// A Conn represents a netlink connection of the nftables family.
//
// All methods return their input, so that variables can be defined from string
// literals when desired.
//
// Commands are buffered. Flush sends all buffered commands in a single batch.
type Conn struct {
	TestDial nltest.Func // for testing only; passed to nltest.Dial
	messages []netlink.Message
	err      error
}

// FlushRuleset flushes the entire ruleset. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Operations_at_ruleset_level
func (cc *Conn) FlushRuleset() {
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELTABLE),
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge | netlink.HeaderFlagsCreate,
		},
		Data: extraHeader(0, 0),
	})
}

// AddTable adds the specified Table. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Configuring_tables
func (cc *Conn) AddTable(t *Table) *Table {
	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_TABLE_NAME, Data: []byte(t.Name + "\x00")},
		{Type: unix.NFTA_TABLE_FLAGS, Data: []byte{0, 0, 0, 0}},
	})
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWTABLE),
			Flags: netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge | netlink.HeaderFlagsCreate,
		},
		Data: append(extraHeader(uint8(t.Family), 0), data...),
	})
	return t
}

// Flush sends all buffered commands in a single batch to nftables.
func (cc *Conn) Flush() error {
	if cc.err != nil {
		return cc.err // serialization error
	}
	var conn *netlink.Conn
	var err error
	if cc.TestDial == nil {
		conn, err = netlink.Dial(unix.NETLINK_NETFILTER, nil)
	} else {
		conn = nltest.Dial(cc.TestDial)
	}
	if err != nil {
		return err
	}

	defer conn.Close()

	if _, err := conn.SendMessages(batch(cc.messages)); err != nil {
		return fmt.Errorf("SendMessages: %v", err)
	}

	if _, err := conn.Receive(); err != nil {
		return fmt.Errorf("Receive: %v", err)
	}

	cc.messages = nil

	return nil
}
