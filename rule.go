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
	"github.com/google/nftables/internal/parseexprfunc"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	newRuleHeaderType = nftMsgNewRule.HeaderType()
	delRuleHeaderType = nftMsgDelRule.HeaderType()
)

// This constant is missing at unix.NFTA_RULE_POSITION_ID.
// TODO: Add the constant in unix and then remove it here.
const nfta_rule_position_id = 0xa

type ruleOperation uint32

// Possible PayloadOperationType values.
const (
	operationAdd ruleOperation = iota
	operationInsert
	operationReplace
)

// A Rule does something with a packet. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Simple_rule_management
type Rule struct {
	Table *Table
	Chain *Chain
	// Handle identifies an existing Rule. For a new Rule, this field is set
	// during the Flush() in which the rule is committed. Make sure to not access
	// this field concurrently with this Flush() to avoid data races.
	Handle uint64
	// ID is an identifier for a new Rule, which is assigned by
	// AddRule/InsertRule, and only valid before the rule is committed by Flush().
	// The field is set to 0 during Flush().
	ID uint32
	// Position can be set to the Handle of another Rule to insert the new Rule
	// before (InsertRule) or after (AddRule) the existing rule.
	Position uint64
	// PositionID can be set to the ID of another Rule, same as Position, for when
	// the existing rule is not yet committed.
	PositionID uint32
	// Deprecated: The feature for which this field was added never worked.
	// The field may be removed in a later version.
	Flags    uint32
	Exprs    []expr.Any
	UserData []byte
}

// GetRule returns the rules in the specified table and chain.
//
// Deprecated: use GetRuleByHandle instead.
func (cc *Conn) GetRule(t *Table, c *Chain) ([]*Rule, error) {
	return cc.GetRules(t, c)
}

// GetRuleByHandle returns the rule in the specified table and chain by its
// handle.
// https://docs.kernel.org/networking/netlink_spec/nftables.html#getrule
func (cc *Conn) GetRuleByHandle(t *Table, c *Chain, handle uint64) (*Rule, error) {
	rules, err := cc.getRules(t, c, nftMsgGetRule, handle)
	if err != nil {
		return nil, err
	}

	if got, want := len(rules), 1; got != want {
		return nil, fmt.Errorf("expected rule count %d, got %d", want, got)
	}

	return rules[0], nil
}

// GetRules returns the rules in the specified table and chain.
func (cc *Conn) GetRules(t *Table, c *Chain) ([]*Rule, error) {
	return cc.getRules(t, c, nftMsgGetRule, 0)
}

// ResetRule resets the stateful expressions (e.g., counters) of the given
// rule. The reset is applied immediately (no Flush is required). The returned
// rule reflects its state prior to the reset. The provided rule must have a
// valid Handle.
// https://docs.kernel.org/networking/netlink_spec/nftables.html#getrule-reset
func (cc *Conn) ResetRule(t *Table, c *Chain, handle uint64) (*Rule, error) {
	if handle == 0 {
		return nil, fmt.Errorf("rule must have a valid handle")
	}

	rules, err := cc.getRules(t, c, nftMsgGetRuleReset, handle)
	if err != nil {
		return nil, err
	}

	if got, want := len(rules), 1; got != want {
		return nil, fmt.Errorf("expected rule count %d, got %d", want, got)
	}

	return rules[0], nil
}

// ResetRules resets the stateful expressions (e.g., counters) of all rules
// in the given table and chain. The reset is applied immediately (no Flush
// is required). The returned rules reflect their state prior to the reset.
// state.
// https://docs.kernel.org/networking/netlink_spec/nftables.html#getrule-reset
func (cc *Conn) ResetRules(t *Table, c *Chain) ([]*Rule, error) {
	return cc.getRules(t, c, nftMsgGetRuleReset, 0)
}

// getRules retrieves rules from the given table and chain, using the provided
// msgType (either NFT_MSG_GETRULE or NFT_MSG_GETRULE_RESET). If the
// handle is non-zero, the operation applies only to the rule with that handle.
func (cc *Conn) getRules(t *Table, c *Chain, msgType nftMsgType, handle uint64) ([]*Rule, error) {
	conn, closer, err := cc.netlinkConn()
	if err != nil {
		return nil, err
	}
	defer func() { _ = closer() }()

	attrs := []netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(t.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(c.Name + "\x00")},
	}

	var flags netlink.HeaderFlags = netlink.Request | netlink.Dump

	if handle != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type: unix.NFTA_RULE_HANDLE,
			Data: binaryutil.BigEndian.PutUint64(handle),
		})

		flags = netlink.Request
	}

	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	message := netlink.Message{
		Header: netlink.Header{
			Type:  msgType.HeaderType(),
			Flags: flags,
		},
		Data: append(extraHeader(uint8(t.Family), 0), data...),
	}

	if _, err := conn.SendMessages([]netlink.Message{message}); err != nil {
		return nil, fmt.Errorf("SendMessages: %v", err)
	}

	reply, err := cc.receive(conn)
	if err != nil {
		return nil, fmt.Errorf("receive: %v", err)
	}
	var rules []*Rule
	for _, msg := range reply {
		r, err := ruleFromMsg(t.Family, msg)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}

	return rules, nil
}

func (cc *Conn) newRule(r *Rule, op ruleOperation) *Rule {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	exprAttrs := make([]netlink.Attribute, len(r.Exprs))
	for idx, expr := range r.Exprs {
		exprAttrs[idx] = netlink.Attribute{
			Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM,
			Data: cc.marshalExpr(byte(r.Table.Family), expr),
		}
	}

	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(r.Table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(r.Chain.Name + "\x00")},
	})

	if r.Handle != 0 {
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(r.Handle)},
		})...)
	} else {
		r.ID = cc.allocateTransactionID()
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_ID, Data: binaryutil.BigEndian.PutUint32(r.ID)},
		})...)
	}

	data = append(data, cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: cc.marshalAttr(exprAttrs)},
	})...)

	if compatPolicy, err := getCompatPolicy(r.Exprs); err != nil {
		cc.setErr(err)
	} else if compatPolicy != nil {
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_COMPAT, Data: cc.marshalAttr([]netlink.Attribute{
				{Type: unix.NFTA_RULE_COMPAT_PROTO, Data: binaryutil.BigEndian.PutUint32(compatPolicy.Proto)},
				{Type: unix.NFTA_RULE_COMPAT_FLAGS, Data: binaryutil.BigEndian.PutUint32(compatPolicy.Flag & nft_RULE_COMPAT_F_MASK)},
			})},
		})...)
	}

	msgData := []byte{}

	msgData = append(msgData, data...)
	if r.UserData != nil {
		msgData = append(msgData, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_USERDATA, Data: r.UserData},
		})...)
	}

	var flags netlink.HeaderFlags
	var ruleRef *Rule
	switch op {
	case operationAdd:
		flags = netlink.Request | netlink.Create | netlink.Echo | netlink.Append
		ruleRef = r
	case operationInsert:
		flags = netlink.Request | netlink.Create | netlink.Echo
		ruleRef = r
	case operationReplace:
		flags = netlink.Request | netlink.Replace
	}

	if r.Position != 0 {
		msgData = append(msgData, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_POSITION, Data: binaryutil.BigEndian.PutUint64(r.Position)},
		})...)
	} else if r.PositionID != 0 {
		msgData = append(msgData, cc.marshalAttr([]netlink.Attribute{
			{Type: nfta_rule_position_id, Data: binaryutil.BigEndian.PutUint32(r.PositionID)},
		})...)
	}

	cc.messages = append(cc.messages, netlinkMessage{
		Header: netlink.Header{
			Type:  newRuleHeaderType,
			Flags: flags,
		},
		Data: append(extraHeader(uint8(r.Table.Family), 0), msgData...),
		rule: ruleRef,
	})

	return r
}

func (r *Rule) handleCreateReply(reply netlink.Message) error {
	ad, err := netlink.NewAttributeDecoder(reply.Data[4:])
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	var handle uint64
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_RULE_HANDLE:
			handle = ad.Uint64()
		}
	}
	if ad.Err() != nil {
		return ad.Err()
	}
	if handle == 0 {
		return fmt.Errorf("missing rule handle in create reply")
	}
	r.Handle = handle
	r.ID = 0
	return nil
}

func (cc *Conn) ReplaceRule(r *Rule) *Rule {
	return cc.newRule(r, operationReplace)
}

// AddRule inserts the specified Rule after the existing Rule referenced by
// Position/PositionID if set, otherwise at the end of the chain.
func (cc *Conn) AddRule(r *Rule) *Rule {
	if r.Handle != 0 {
		return cc.newRule(r, operationReplace)
	}

	return cc.newRule(r, operationAdd)
}

// InsertRule inserts the specified Rule before the existing Rule referenced by
// Position/PositionID if set, otherwise at the beginning of the chain.
func (cc *Conn) InsertRule(r *Rule) *Rule {
	if r.Handle != 0 {
		return cc.newRule(r, operationReplace)
	}

	return cc.newRule(r, operationInsert)
}

// DelRule deletes the specified Rule. Either the Handle or ID of the
// rule must be set.
func (cc *Conn) DelRule(r *Rule) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(r.Table.Name + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(r.Chain.Name + "\x00")},
	})
	if r.Handle != 0 {
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_HANDLE, Data: binaryutil.BigEndian.PutUint64(r.Handle)},
		})...)
	} else if r.ID != 0 {
		data = append(data, cc.marshalAttr([]netlink.Attribute{
			{Type: unix.NFTA_RULE_ID, Data: binaryutil.BigEndian.PutUint32(r.ID)},
		})...)
	} else {
		err := fmt.Errorf("rule must have a handle or ID")
		cc.setErr(err)
		return err
	}
	flags := netlink.Request

	cc.messages = append(cc.messages, netlinkMessage{
		Header: netlink.Header{
			Type:  delRuleHeaderType,
			Flags: flags,
		},
		Data: append(extraHeader(uint8(r.Table.Family), 0), data...),
	})

	return nil
}

func ruleFromMsg(fam TableFamily, msg netlink.Message) (*Rule, error) {
	if got, want1, want2 := msg.Header.Type, newRuleHeaderType, delRuleHeaderType; got != want1 && got != want2 {
		return nil, fmt.Errorf("unexpected header type: got %v, want %v or %v", msg.Header.Type, want1, want2)
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
			r.Table = &Table{
				Name:   ad.String(),
				Family: fam,
			}
		case unix.NFTA_RULE_CHAIN:
			r.Chain = &Chain{Name: ad.String()}
		case unix.NFTA_RULE_EXPRESSIONS:
			ad.Do(func(b []byte) error {
				exprs, err := parseexprfunc.ParseExprMsgFunc(byte(fam), b)
				if err != nil {
					return err
				}
				r.Exprs = make([]expr.Any, len(exprs))
				for i := range exprs {
					r.Exprs[i] = exprs[i].(expr.Any)
				}
				return nil
			})
		case unix.NFTA_RULE_POSITION:
			r.Position = ad.Uint64()
		case unix.NFTA_RULE_HANDLE:
			r.Handle = ad.Uint64()
		case unix.NFTA_RULE_USERDATA:
			r.UserData = ad.Bytes()
		}
	}
	return &r, ad.Err()
}
