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

package nftables

import (
	"encoding/binary"
	"fmt"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var ruleHeaderType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWRULE)

// A Rule does something with a packet. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management
type Rule struct {
	Table    *Table
	Chain    *Chain
	RuleID   uint32
	Position uint64
	Handle   uint64
	Exprs    []expr.Any
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
			Flags: netlink.Request | netlink.Acknowledge | netlink.Dump | unix.NLM_F_ECHO,
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

// GetRuleHandle returns a specific rule's handle. Rule is identified by Table, Chain and RuleID.
func (cc *Conn) GetRuleHandle(t *Table, c *Chain, ruleID uint32) (uint64, error) {
	conn, err := cc.dialNetlink()
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if ruleID == 0 {
		return 0, fmt.Errorf("rule's id cannot be 0")
	}

	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(t.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(c.Name + "\x00")},
		{Type: unix.NFTA_RULE_USERDATA, Data: binaryutil.BigEndian.PutUint32(ruleID)},
	})
	if err != nil {
		return 0, err
	}
	message := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Dump | unix.NLM_F_ECHO,
		},
		Data: append(extraHeader(uint8(t.Family), 0), data...),
	}
	if _, err := conn.SendMessages([]netlink.Message{message}); err != nil {
		return 0, fmt.Errorf("SendMessages: %v", err)
	}
	reply, err := conn.Receive()
	if err != nil {
		return 0, fmt.Errorf("Receive: %v", err)
	}
	for _, msg := range reply {
		rr, err := ruleFromMsg(msg)
		if err != nil {
			return 0, err
		}
		if rr.RuleID == ruleID {
			return rr.Handle, nil
		}
	}

	return 0, fmt.Errorf("rule with id %d is not found", ruleID)
}

// AddRule adds the specified Rule
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
	msgData := []byte{}
	msgData = append(msgData, data...)
	var flags netlink.HeaderFlags
	if r.RuleID != 0 {
		msgData = append(msgData, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_USERDATA, Data: binaryutil.BigEndian.PutUint32(r.RuleID)},
		})...)
	}
	if r.Position != 0 {
		msgData = append(msgData, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_POSITION, Data: binaryutil.BigEndian.PutUint64(r.Position)},
		})...)
		// when a rule's position is specified, it becomes nft insert rule operation
		flags = netlink.Request | netlink.Acknowledge | netlink.Create | unix.NLM_F_ECHO
	} else {
		// unix.NLM_F_APPEND is added when nft add rule operation is executed.
		flags = netlink.Request | netlink.Acknowledge | netlink.Create | unix.NLM_F_ECHO | unix.NLM_F_APPEND
	}
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  ruleHeaderType,
			Flags: flags,
		},
		Data: append(extraHeader(uint8(r.Table.Family), 0), msgData...),
	})

	return r
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
		case unix.NFTA_RULE_POSITION:
			r.Position = ad.Uint64()
		case unix.NFTA_RULE_HANDLE:
			r.Handle = ad.Uint64()
		case unix.NFTA_RULE_USERDATA:
			r.RuleID = ad.Uint32()
		}
	}
	return &r, ad.Err()
}
