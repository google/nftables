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
	"math"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

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
