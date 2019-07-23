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
	"errors"
	"fmt"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var allocSetID uint32

// SetDatatype represents a datatype declared by nft.
type SetDatatype struct {
	Name  string
	Bytes uint32

	// nftMagic represents the magic value that nft uses for
	// certain types (ie: IP addresses). We populate SET_KEY_TYPE
	// identically, so `nft list ...` commands produce correct output.
	nftMagic uint32
}

// NFT datatypes. See: https://git.netfilter.org/nftables/tree/src/datatype.c
var (
	TypeInvalid     = SetDatatype{Name: "invalid", nftMagic: 1}
	TypeIPAddr      = SetDatatype{Name: "ipv4_addr", Bytes: 4, nftMagic: 7}
	TypeIP6Addr     = SetDatatype{Name: "ipv6_addr", Bytes: 16, nftMagic: 8}
	TypeEtherAddr   = SetDatatype{Name: "ether_addr", Bytes: 6, nftMagic: 9}
	TypeInetProto   = SetDatatype{Name: "inet_proto", Bytes: 1, nftMagic: 12}
	TypeInetService = SetDatatype{Name: "inet_service", Bytes: 2, nftMagic: 13}

	nftDatatypes = []SetDatatype{
		TypeIPAddr,
		TypeIP6Addr,
		TypeEtherAddr,
		TypeInetProto,
		TypeInetService,
	}
)

// Set represents an nftables set. Anonymous sets are only valid within the
// context of a single batch.
type Set struct {
	Table     *Table
	ID        uint32
	Name      string
	Anonymous bool
	Constant  bool

	KeyType SetDatatype
	DataLen int
}

// SetElement represents a data point within a set.
type SetElement struct {
	Key []byte
	Val []byte
}

// SetAddElements applies data points to an nftables set.
func (cc *Conn) SetAddElements(s *Set, vals []SetElement) error {
	if s.Anonymous {
		return errors.New("anonymous sets cannot be updated")
	}

	elements, err := s.makeElemList(vals)
	if err != nil {
		return err
	}
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWSETELEM),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: append(extraHeader(unix.NFTA_SET_NAME, 0), cc.marshalAttr(elements)...),
	})

	return nil
}

func (s *Set) makeElemList(vals []SetElement) ([]netlink.Attribute, error) {
	var elements []netlink.Attribute
	for i, v := range vals {
		encodedKey, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_DATA_VALUE, Data: v.Key}})
		if err != nil {
			return nil, fmt.Errorf("marshal key %d: %v", i, err)
		}
		item := []netlink.Attribute{{Type: unix.NFTA_SET_ELEM_KEY | unix.NLA_F_NESTED, Data: encodedKey}}

		if len(v.Val) > 0 {
			encodedVal, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_DATA_VALUE, Data: v.Val}})
			if err != nil {
				return nil, fmt.Errorf("marshal item %d: %v", i, err)
			}
			item = append(item, netlink.Attribute{Type: unix.NFTA_SET_ELEM_DATA | unix.NLA_F_NESTED, Data: encodedVal})
		}

		encodedItem, err := netlink.MarshalAttributes(item)
		if err != nil {
			return nil, fmt.Errorf("marshal item %d: %v", i, err)
		}
		elements = append(elements, netlink.Attribute{Type: uint16(i+1) | unix.NLA_F_NESTED, Data: encodedItem})
	}

	encodedElem, err := netlink.MarshalAttributes(elements)
	if err != nil {
		return nil, fmt.Errorf("marshal elements: %v", err)
	}

	return []netlink.Attribute{
		{Type: unix.NFTA_SET_NAME, Data: []byte(s.Name + "\x00")},
		{Type: unix.NFTA_SET_KEY_TYPE, Data: binaryutil.BigEndian.PutUint32(unix.NFTA_DATA_VALUE)},
		{Type: unix.NFTA_SET_TABLE, Data: []byte(s.Table.Name + "\x00")},
		{Type: unix.NFTA_SET_ELEM_LIST_ELEMENTS | unix.NLA_F_NESTED, Data: encodedElem},
	}, nil
}

// AddSet adds the specified Set.
func (cc *Conn) AddSet(s *Set, vals []SetElement) error {
	// Based on nft implementation & linux source.
	// Link: https://github.com/torvalds/linux/blob/49a57857aeea06ca831043acbb0fa5e0f50602fd/net/netfilter/nf_tables_api.c#L3395
	// Another reference: https://git.netfilter.org/nftables/tree/src

	if s.Anonymous && !s.Constant {
		return errors.New("anonymous structs must be constant")
	}

	if s.ID == 0 {
		allocSetID++
		s.ID = allocSetID
		if s.Anonymous {
			s.Name = "__set%d"
		}
	}

	setData := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_SET_DESC_SIZE, Data: binaryutil.BigEndian.PutUint32(uint32(len(vals)))},
	})

	var flags uint32
	if s.Anonymous {
		flags |= unix.NFT_SET_ANONYMOUS
	}
	if s.Constant {
		flags |= unix.NFT_SET_CONSTANT
	}
	if s.DataLen > 0 {
		flags |= unix.NFT_SET_MAP
	}

	tableInfo := []netlink.Attribute{
		{Type: unix.NFTA_SET_TABLE, Data: []byte(s.Table.Name + "\x00")},
		{Type: unix.NFTA_SET_NAME, Data: []byte(s.Name + "\x00")},
		{Type: unix.NFTA_SET_ELEM_FLAGS, Data: binaryutil.BigEndian.PutUint32(flags)},
		{Type: unix.NFTA_SET_KEY_TYPE, Data: binaryutil.BigEndian.PutUint32(s.KeyType.nftMagic)},
		{Type: unix.NFTA_SET_KEY_LEN, Data: binaryutil.BigEndian.PutUint32(s.KeyType.Bytes)},
		{Type: unix.NFTA_SET_ID, Data: binaryutil.BigEndian.PutUint32(s.ID)},
	}
	if s.DataLen > 0 {
		tableInfo = append(tableInfo, netlink.Attribute{Type: unix.NFTA_SET_DATA_TYPE, Data: binaryutil.BigEndian.PutUint32(unix.NFT_DATA_VALUE)},
			netlink.Attribute{Type: unix.NFTA_SET_DATA_LEN, Data: binaryutil.BigEndian.PutUint32(uint32(s.DataLen))})
	}
	if s.Anonymous || s.Constant {
		tableInfo = append(tableInfo, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_SET_DESC, Data: setData},
			// Semantically useless - kept for binary compatability with nft
			netlink.Attribute{Type: unix.NFTA_SET_USERDATA, Data: []byte("\x00\x04\x02\x00\x00\x00")})
	}

	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWSET),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: append(extraHeader(uint8(s.Table.Family), 0), cc.marshalAttr(tableInfo)...),
	})

	// Set the values of the set if initial values were provided.
	if len(vals) > 0 {
		hdrType := unix.NFT_MSG_NEWSETELEM
		if s.Anonymous {
			// Anonymous sets can only be populated within NEWSET.
			hdrType = unix.NFT_MSG_NEWSET
		}
		elements, err := s.makeElemList(vals)
		if err != nil {
			return err
		}
		cc.messages = append(cc.messages, netlink.Message{
			Header: netlink.Header{
				Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | hdrType),
				Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
			},
			Data: append(extraHeader(uint8(s.Table.Family), 0), cc.marshalAttr(elements)...),
		})
	}

	return nil
}

// DelSet deletes a specific set, along with all elements it contains.
func (cc *Conn) DelSet(s *Set) {
	data := cc.marshalAttr([]netlink.Attribute{
		{Type: unix.NFTA_SET_TABLE, Data: []byte(s.Table.Name + "\x00")},
		{Type: unix.NFTA_SET_NAME, Data: []byte(s.Name + "\x00")},
	})
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELSET),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(extraHeader(uint8(s.Table.Family), 0), data...),
	})
}

// SetDeleteElements deletes data points from an nftables set.
func (cc *Conn) SetDeleteElements(s *Set, vals []SetElement) error {
	if s.Anonymous {
		return errors.New("anonymous sets cannot be updated")
	}

	elements, err := s.makeElemList(vals)
	if err != nil {
		return err
	}
	cc.messages = append(cc.messages, netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELSETELEM),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: append(extraHeader(uint8(s.Table.Family), 0), cc.marshalAttr(elements)...),
	})

	return nil
}

var setHeaderType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWSET)

func setsFromMsg(msg netlink.Message) (*Set, error) {
	if got, want := msg.Header.Type, setHeaderType; got != want {
		return nil, fmt.Errorf("unexpected header type: got %v, want %v", got, want)
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian

	var set Set
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_SET_NAME:
			set.Name = ad.String()
		case unix.NFTA_SET_ID:
			set.ID = binary.BigEndian.Uint32(ad.Bytes())
		case unix.NFTA_SET_FLAGS:
			flags := ad.Uint32()
			set.Constant = (flags & unix.NFT_SET_CONSTANT) != 0
			set.Anonymous = (flags & unix.NFT_SET_ANONYMOUS) != 0
		case unix.NFTA_SET_KEY_TYPE:
			nftMagic := ad.Uint32()
			for _, dt := range nftDatatypes {
				if nftMagic == dt.nftMagic {
					set.KeyType = dt
					break
				}
			}
			if set.KeyType.nftMagic == 0 {
				return nil, fmt.Errorf("could not determine datatype %x", nftMagic)
			}
		}
	}
	return &set, nil
}

var elemHeaderType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_NEWSETELEM)

func elementsFromMsg(msg netlink.Message) ([]SetElement, error) {
	if got, want := msg.Header.Type, elemHeaderType; got != want {
		return nil, fmt.Errorf("unexpected header type: got %v, want %v", got, want)
	}
	ad, err := netlink.NewAttributeDecoder(msg.Data[4:])
	if err != nil {
		return nil, err
	}
	ad.ByteOrder = binary.BigEndian

	var elements []SetElement
	for ad.Next() {
		b := ad.Bytes()
		if ad.Type() == unix.NFTA_SET_ELEM_LIST_ELEMENTS && len(b) > 8 {
			ad, err := netlink.NewAttributeDecoder(b[8:])
			if err != nil {
				return nil, err
			}
			ad.ByteOrder = binary.BigEndian

			var elem SetElement
			for ad.Next() {
				switch ad.Type() {
				case unix.NFTA_SET_ELEM_KEY:
					elem.Key = ad.Bytes()
				case unix.NFTA_SET_ELEM_DATA:
					elem.Val = ad.Bytes()
				}
			}
			elements = append(elements, elem)
		}
	}
	return elements, nil
}

// GetSets returns the sets in the specified table.
func (cc *Conn) GetSets(t *Table) ([]*Set, error) {
	conn, err := cc.dialNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_SET_TABLE, Data: []byte(t.Name + "\x00")},
	})
	if err != nil {
		return nil, err
	}

	message := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETSET),
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
	var sets []*Set
	for _, msg := range reply {
		s, err := setsFromMsg(msg)
		if err != nil {
			return nil, err
		}
		sets = append(sets, s)
	}

	return sets, nil
}

// GetSetElements returns the elements in the specified set.
func (cc *Conn) GetSetElements(s *Set) ([]SetElement, error) {
	conn, err := cc.dialNetlink()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_SET_TABLE, Data: []byte(s.Table.Name + "\x00")},
		{Type: unix.NFTA_SET_NAME, Data: []byte(s.Name + "\x00")},
	})
	if err != nil {
		return nil, err
	}

	message := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETSETELEM),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Dump,
		},
		Data: append(extraHeader(uint8(s.Table.Family), 0), data...),
	}

	if _, err := conn.SendMessages([]netlink.Message{message}); err != nil {
		return nil, fmt.Errorf("SendMessages: %v", err)
	}

	reply, err := conn.Receive()
	if err != nil {
		return nil, fmt.Errorf("Receive: %v", err)
	}
	var elems []SetElement
	for _, msg := range reply {
		s, err := elementsFromMsg(msg)
		if err != nil {
			return nil, err
		}
		elems = append(elems, s...)
	}

	return elems, nil
}
