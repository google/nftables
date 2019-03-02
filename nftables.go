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
	"encoding/binary"
	"fmt"
	"math"
	"strings"

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
	}, binaryutil.BigEndian.PutUint16(resID)...)
}

func batch(messages []netlink.Message) []netlink.Message {
	batch := []netlink.Message{
		{
			Header: netlink.Header{
				Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_BEGIN),
				Flags: netlink.Request,
			},
			Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
		},
	}

	batch = append(batch, messages...)

	batch = append(batch, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_END),
			Flags: netlink.Request,
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
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: append(extraHeader(uint8(c.Table.Family), 0), data...),
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

var ruleHeaderType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWRULE)

func stringFrom0(b []byte) string {
	return strings.TrimSuffix(string(b), "\x00")
}

func exprsFromMsg(b []byte) ([]expr.Any, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian
	var exprs []expr.Any
	for ad.Next() {
		ad.Do(func(b []byte) error {
			ad, err := netlink.NewAttributeDecoder(b)
			if err != nil {
				return err
			}
			ad.ByteOrder = binary.BigEndian
			var name string
			for ad.Next() {
				switch ad.Type() {
				case unix.NFTA_EXPR_NAME:
					name = ad.String()
				case unix.NFTA_EXPR_DATA:
					var e expr.Any
					switch name {
					case "meta":
						e = &expr.Meta{}
					case "cmp":
						e = &expr.Cmp{}
					case "counter":
						e = &expr.Counter{}
					case "payload":
						e = &expr.Payload{}
					case "lookup":
						e = &expr.Lookup{}
					case "immediate":
						e = &expr.Immediate{}
					}
					if e == nil {
						// TODO: introduce an opaque expression type so that users know
						// something is here.
						continue // unsupported expression type
					}

					ad.Do(func(b []byte) error {
						if err := expr.Unmarshal(b, e); err != nil {
							return err
						}
						// Verdict expressions are a special-case of immediate expressions, so
						// if the expression is an immediate writing nothing into the verdict
						// register (invalid), re-parse it as a verdict expression.
						if imm, isImmediate := e.(*expr.Immediate); isImmediate && imm.Register == unix.NFT_REG_VERDICT && len(imm.Data) == 0 {
							e = &expr.Verdict{}
							if err := expr.Unmarshal(b, e); err != nil {
								return err
							}
						}
						exprs = append(exprs, e)
						return nil
					})
				}
			}
			return ad.Err()
		})
	}
	return exprs, ad.Err()
}

func ruleFromMsg(msg netlink.Message) (*Rule, error) {
	if got, want := msg.Header.Type, ruleHeaderType; got != want {
		return nil, fmt.Errorf("unexpected header type: got %v, want %v", got, want)
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian
	var r Rule
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_TABLE:
			r.Table = &Table{Name: ad.String()}
		case unix.NFTA_RULE_CHAIN:
			r.Chain = &Chain{Name: ad.String()}
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Do(func(b []byte) error {
				r.Exprs, err = exprsFromMsg(b)
				return err
			})
		}
	}
	return &r, ad.Err()
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
			Type:  ruleHeaderType,
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: append(extraHeader(uint8(r.Table.Family), 0), data...),
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
	NetNS    int         // Network namespace netlink will interact with.
	messages []netlink.Message
	err      error
}

// FlushRuleset flushes the entire ruleset. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Operations_at_ruleset_level
func (cc *Conn) FlushRuleset() {
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELTABLE),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: extraHeader(0, 0),
	})
}

// DelTable deletes a specific table, along with all chains/rules it contains.
func (cc *Conn) DelTable(t *Table) {
	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_TABLE_NAME, Data: []byte(t.Name + "\x00")},
		{Type: unix.NFTA_TABLE_FLAGS, Data: []byte{0, 0, 0, 0}},
	})
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELTABLE),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(extraHeader(uint8(t.Family), 0), data...),
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
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
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
	conn, err := cc.dialNetlink()
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

// GetRule returns the rules in the specified table and chain.
func (cc *Conn) GetRule(t *Table, c *Chain) ([]*Rule, error) {
	conn, err := cc.dialNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(t.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(c.Name + "\x00")},
	})
	if err != nil {
		return nil, err
	}

	message := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Dump,
		},
		Data: append(extraHeader(uint8(t.Family), 0), data...),
	}

	if _, err := conn.SendMessages([]netlink.Message{message}); err != nil {
		return nil, fmt.Errorf("SendMessages: %v", err)
	}

	reply, err := conn.Receive()
	if err != nil {
		return nil, fmt.Errorf("Receive: %v", err)
	}
	var rules []*Rule
	for _, msg := range reply {
		r, err := ruleFromMsg(msg)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}

	return rules, nil
}

// CounterObj implements Obj.
type CounterObj struct {
	Table *Table
	Name  string // e.g. “fwded”

	Bytes   uint64
	Packets uint64
}

func (c *CounterObj) unmarshal(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_COUNTER_BYTES:
			c.Bytes = ad.Uint64()
		case unix.NFTA_COUNTER_PACKETS:
			c.Packets = ad.Uint64()
		}
	}
	return ad.Err()
}

func (c *CounterObj) family() TableFamily {
	return c.Table.Family
}

func (c *CounterObj) marshal(data bool) ([]byte, error) {
	obj, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_COUNTER_BYTES, Data: binaryutil.BigEndian.PutUint64(c.Bytes)},
		{Type: unix.NFTA_COUNTER_PACKETS, Data: binaryutil.BigEndian.PutUint64(c.Packets)},
	})
	if err != nil {
		return nil, err
	}
	const NFT_OBJECT_COUNTER = 1 // TODO: get into x/sys/unix
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_OBJ_TABLE, Data: []byte(c.Table.Name + "\x00")},
		{Type: unix.NFTA_OBJ_NAME, Data: []byte(c.Name + "\x00")},
		{Type: unix.NFTA_OBJ_TYPE, Data: binaryutil.BigEndian.PutUint32(NFT_OBJECT_COUNTER)},
	}
	if data {
		attrs = append(attrs, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_OBJ_DATA, Data: obj})
	}
	return netlink.MarshalAttributes(attrs)
}

// Obj represents a netfilter stateful object. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Stateful_objects
type Obj interface {
	family() TableFamily
	unmarshal(*netlink.AttributeDecoder) error
	marshal(data bool) ([]byte, error)
}

// AddObj adds the specified Obj. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Stateful_objects
func (cc *Conn) AddObj(o Obj) Obj {
	data, err := o.marshal(true)
	if err != nil {
		cc.setErr(err)
		return nil
	}

	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWOBJ),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: append(extraHeader(uint8(o.family()), 0), data...),
	})
	return o
}

var objHeaderType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWOBJ)

func objFromMsg(msg netlink.Message) (Obj, error) {
	if got, want := msg.Header.Type, objHeaderType; got != want {
		return nil, fmt.Errorf("unexpected header type: got %v, want %v", got, want)
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian
	var (
		table      *Table
		name       string
		objectType uint32
	)
	const NFT_OBJECT_COUNTER = 1 // TODO: get into x/sys/unix
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_OBJ_TABLE:
			table = &Table{Name: ad.String(), Family: TableFamily(msg.Data[0])}
		case unix.NFTA_OBJ_NAME:
			name = ad.String()
		case unix.NFTA_OBJ_TYPE:
			objectType = ad.Uint32()
		case unix.NFTA_OBJ_DATA:
			switch objectType {
			case NFT_OBJECT_COUNTER:
				o := CounterObj{
					Table: table,
					Name:  name,
				}

				ad.Do(func(b []byte) error {
					ad, err := netlink.NewAttributeDecoder(b)
					if err != nil {
						return err
					}
					ad.ByteOrder = binary.BigEndian
					return o.unmarshal(ad)
				})
				return &o, ad.Err()
			}
		}
	}
	if err := ad.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("malformed stateful object")
}

func (cc *Conn) dialNetlink() (*netlink.Conn, error) {
	if cc.TestDial != nil {
		return nltest.Dial(cc.TestDial), nil
	}
	return netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: cc.NetNS})
}

func (cc *Conn) getObj(o Obj, msgType uint16) ([]Obj, error) {
	conn, err := cc.dialNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	data, err := o.marshal(false)
	if err != nil {
		return nil, err
	}

	message := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | msgType),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Dump,
		},
		Data: append(extraHeader(uint8(o.family()), 0), data...),
	}

	if _, err := conn.SendMessages([]netlink.Message{message}); err != nil {
		return nil, fmt.Errorf("SendMessages: %v", err)
	}

	reply, err := conn.Receive()
	if err != nil {
		return nil, fmt.Errorf("Receive: %v", err)
	}
	var objs []Obj
	for _, msg := range reply {
		o, err := objFromMsg(msg)
		if err != nil {
			return nil, err
		}
		objs = append(objs, o)
	}

	return objs, nil
}

// GetObj gets the specified Obj without resetting it.
func (cc *Conn) GetObj(o Obj) ([]Obj, error) {
	return cc.getObj(o, unix.NFT_MSG_GETOBJ)
}

// GetObjReset gets the specified Obj and resets it.
func (cc *Conn) GetObjReset(o Obj) ([]Obj, error) {
	return cc.getObj(o, unix.NFT_MSG_GETOBJ_RESET)
}
