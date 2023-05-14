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
	"sync"

	"golang.org/x/sys/unix"
)

type MonitorEvent uint8

const (
	MonitorEventNew MonitorEvent = 1 << iota
	MonitorEventDel
	MonitorEventMask MonitorEvent = (1 << iota) - 1
	MonitorEventAny  MonitorEvent = MonitorEventMask
)

type MonitorObject uint32

// Possible MonitorObject values.
const (
	MonitorObjectTables MonitorObject = 1 << iota
	MonitorObjectChains
	MonitorObjectSets
	MonitorObjectRules
	MonitorObjectElements
	MonitorObjectRuleset
	MonitorObjectTrace
	MonitorObjectMask MonitorObject = (1 << iota) - 1
	MonitorObjectAny  MonitorObject = MonitorObjectMask
)

var (
	monitorFlags         map[MonitorEvent]map[MonitorObject]uint32
	monitorFlagsInitOnce sync.Once
)

func lazyInitOnce() {
	monitorFlagsInitOnce.Do(func() {
		monitorFlags = map[MonitorEvent]map[MonitorObject]uint32{
			MonitorEventAny: {
				MonitorObjectAny:      0xffffffff,
				MonitorObjectTables:   1<<unix.NFT_MSG_NEWTABLE | 1<<unix.NFT_MSG_DELCHAIN,
				MonitorObjectChains:   1<<unix.NFT_MSG_NEWCHAIN | 1<<unix.NFT_MSG_DELCHAIN,
				MonitorObjectRules:    1<<unix.NFT_MSG_NEWRULE | 1<<unix.NFT_MSG_DELRULE,
				MonitorObjectSets:     1<<unix.NFT_MSG_NEWSET | 1<<unix.NFT_MSG_DELSET,
				MonitorObjectElements: 1<<unix.NFT_MSG_NEWSETELEM | 1<<unix.NFT_MSG_DELSETELEM,
				MonitorObjectRuleset: 1<<unix.NFT_MSG_NEWTABLE | 1<<unix.NFT_MSG_DELCHAIN |
					1<<unix.NFT_MSG_NEWCHAIN | 1<<unix.NFT_MSG_DELCHAIN |
					1<<unix.NFT_MSG_NEWRULE | 1<<unix.NFT_MSG_DELRULE |
					1<<unix.NFT_MSG_NEWSET | 1<<unix.NFT_MSG_DELSET |
					1<<unix.NFT_MSG_NEWSETELEM | 1<<unix.NFT_MSG_DELSETELEM |
					1<<unix.NFT_MSG_NEWOBJ | 1<<unix.NFT_MSG_DELOBJ,
				MonitorObjectTrace: 1 << unix.NFT_MSG_TRACE,
			},
			MonitorEventNew: {
				MonitorObjectAny: 1<<unix.NFT_MSG_NEWTABLE |
					1<<unix.NFT_MSG_NEWCHAIN |
					1<<unix.NFT_MSG_NEWRULE |
					1<<unix.NFT_MSG_NEWSET |
					1<<unix.NFT_MSG_NEWSETELEM,
				MonitorObjectTables: 1 << unix.NFT_MSG_NEWTABLE,
				MonitorObjectChains: 1 << unix.NFT_MSG_NEWCHAIN,
				MonitorObjectRules:  1 << unix.NFT_MSG_NEWRULE,
				MonitorObjectSets:   1 << unix.NFT_MSG_NEWSET,
				MonitorObjectRuleset: 1<<unix.NFT_MSG_NEWTABLE |
					1<<unix.NFT_MSG_NEWCHAIN |
					1<<unix.NFT_MSG_NEWRULE |
					1<<unix.NFT_MSG_NEWSET |
					1<<unix.NFT_MSG_NEWSETELEM |
					1<<unix.NFT_MSG_NEWOBJ,
				MonitorObjectTrace: 0,
			},
			MonitorEventDel: {
				MonitorObjectAny: 1<<unix.NFT_MSG_DELTABLE |
					1<<unix.NFT_MSG_DELCHAIN |
					1<<unix.NFT_MSG_DELRULE |
					1<<unix.NFT_MSG_DELSET |
					1<<unix.NFT_MSG_DELSETELEM |
					1<<unix.NFT_MSG_DELOBJ,
				MonitorObjectTrace: 0,
			},
		}
	})
}

type Monitor struct {
	Event      MonitorEvent
	Object     MonitorObject
	BufferSize int
}

func (monitor *Monitor) AddMonitorObject(obj MonitorObject) {
	monitor.Object = monitor.Object | obj
}

type Event struct{}

func (cc *Conn) AddMonitor(monitor *Monitor) (chan *Event, error) {
	_, closer, err := cc.netlinkConn()
	if err != nil {
		return nil, err
	}
	defer func() { _ = closer() }()

	ch := make(chan *Event, monitor.BufferSize)
	return ch, nil
}
