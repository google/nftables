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
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

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
