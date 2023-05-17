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

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type MonitorAction uint8

// Possible MonitorAction values.
const (
	MonitorActionNew MonitorAction = 1 << iota
	MonitorActionDel
	MonitorActionMask MonitorAction = (1 << iota) - 1
	MonitorActionAny  MonitorAction = MonitorActionMask
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
	MonitorObjectMask MonitorObject = (1 << iota) - 1
	MonitorObjectAny  MonitorObject = MonitorObjectMask
)

var (
	monitorFlags         map[MonitorAction]map[MonitorObject]uint32
	monitorFlagsInitOnce sync.Once
)

// A lazy init function to define flags.
func lazyInit() {
	monitorFlagsInitOnce.Do(func() {
		monitorFlags = map[MonitorAction]map[MonitorObject]uint32{
			MonitorActionAny: {
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
			},
			MonitorActionNew: {
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
			},
			MonitorActionDel: {
				MonitorObjectAny: 1<<unix.NFT_MSG_DELTABLE |
					1<<unix.NFT_MSG_DELCHAIN |
					1<<unix.NFT_MSG_DELRULE |
					1<<unix.NFT_MSG_DELSET |
					1<<unix.NFT_MSG_DELSETELEM |
					1<<unix.NFT_MSG_DELOBJ,
			},
		}
	})
}

type EventType int

const (
	EventTypeNewTable   EventType = unix.NFT_MSG_NEWTABLE
	EventTypeDelTable   EventType = unix.NFT_MSG_DELTABLE
	EventTypeNewChain   EventType = unix.NFT_MSG_NEWCHAIN
	EventTypeDELChain   EventType = unix.NFT_MSG_DELCHAIN
	EventTypeNewRule    EventType = unix.NFT_MSG_NEWRULE
	EventTypeDelRule    EventType = unix.NFT_MSG_DELRULE
	EventTypeNewSet     EventType = unix.NFT_MSG_NEWSET
	EventTypeDelSet     EventType = unix.NFT_MSG_DELSET
	EventTypeNewSetElem EventType = unix.NFT_MSG_NEWSETELEM
	EventTypeDelSetElem EventType = unix.NFT_MSG_DELSETELEM
	EventTypeNewObj     EventType = unix.NFT_MSG_NEWOBJ
	EventTypeDelObj     EventType = unix.NFT_MSG_DELOBJ
)

type Event struct {
	Type  EventType
	Data  interface{}
	Error error
}

const (
	monitorOK = iota
	monitorClosed
)

// A Monitor to track actions on objects.
type Monitor struct {
	action       MonitorAction
	object       MonitorObject
	monitorFlags uint32

	// mtx covers eventCh and status
	mtx     sync.Mutex
	eventCh chan *Event
	status  int
	conn    *netlink.Conn
	closer  netlinkCloser
}

type MonitorOption func(*Monitor)

func WithMonitorEventBuffer(size int) MonitorOption {
	return func(monitor *Monitor) {
		monitor.eventCh = make(chan *Event, size)
	}
}

// WithMonitorAction to set monitor actions like new, del or any.
func WithMonitorAction(action MonitorAction) MonitorOption {
	return func(monitor *Monitor) {
		monitor.action = action
	}
}

// WithMonitorObject to set monitor objects.
func WithMonitorObject(object MonitorObject) MonitorOption {
	return func(monitor *Monitor) {
		monitor.object = object
	}
}

// NewMonitor returns a Monitor with options to be started.
func NewMonitor(opts ...MonitorOption) *Monitor {
	lazyInit()

	monitor := &Monitor{
		status: monitorOK,
	}
	for _, opt := range opts {
		opt(monitor)
	}
	if monitor.eventCh == nil {
		monitor.eventCh = make(chan *Event)
	}
	objects, ok := monitorFlags[monitor.action]
	if !ok {
		objects = monitorFlags[MonitorActionAny]
	}
	flags, ok := objects[monitor.object]
	if !ok {
		flags = objects[MonitorObjectAny]
	}
	monitor.monitorFlags = flags
	return monitor
}

func (monitor *Monitor) monitor() {
	for {
		msgs, err := monitor.conn.Receive()
		if err != nil {
			break
		}
		for _, msg := range msgs {
			if got, want := msg.Header.Type&0xff00>>8, netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES); got != want {
				continue
			}
			msgType := msg.Header.Type & 0x00ff
			if monitor.monitorFlags&1<<msgType == 0 {
				continue
			}
			switch msgType {
			case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
				table, err := tableFromMsg(msg)
				event := &Event{
					Type:  EventType(msgType),
					Data:  table,
					Error: err,
				}
				monitor.eventCh <- event
			case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:
				chain, err := chainFromMsg(msg)
				event := &Event{
					Type:  EventType(msgType),
					Data:  chain,
					Error: err,
				}
				monitor.eventCh <- event
			case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
				rule, err := parseRuleFromMsg(msg)
				event := &Event{
					Type:  EventType(msgType),
					Data:  rule,
					Error: err,
				}
				monitor.eventCh <- event
			case unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET:
				set, err := setsFromMsg(msg)
				event := &Event{
					Type:  EventType(msgType),
					Data:  set,
					Error: err,
				}
				monitor.eventCh <- event
			case unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM:
				elems, err := elementsFromMsg(msg)
				event := &Event{
					Type:  EventType(msgType),
					Data:  elems,
					Error: err,
				}
				monitor.eventCh <- event
			case unix.NFT_MSG_NEWOBJ, unix.NFT_MSG_DELOBJ:
				obj, err := objFromMsg(msg)
				event := &Event{
					Type:  EventType(msgType),
					Data:  obj,
					Error: err,
				}
				monitor.eventCh <- event
			case unix.NFT_MSG_TRACE:
			}
		}
	}
	monitor.mtx.Lock()
	if monitor.status != monitorClosed {
		monitor.status = monitorClosed
		monitor.closer()
		close(monitor.eventCh)
	}
	monitor.mtx.Unlock()
}

func (monitor *Monitor) Close() {
	monitor.mtx.Lock()
	if monitor.status != monitorClosed {
		monitor.status = monitorClosed
		monitor.closer()
		close(monitor.eventCh)
	}
	monitor.mtx.Unlock()
}

// AddMonitor to perform the monitor immediately. The channel will be closed after
// calling Close on Monitor or encountering a netlink conn error while Receive.
func (cc *Conn) AddMonitor(monitor *Monitor) (chan *Event, error) {
	conn, closer, err := cc.netlinkConn()
	if err != nil {
		return nil, err
	}
	monitor.conn = conn
	monitor.closer = closer

	if monitor.monitorFlags != 0 {
		err = conn.JoinGroup(uint32(unix.NFNLGRP_NFTABLES))
		if err != nil {
			monitor.closer()
			return nil, err
		}
		conn.JoinGroup(uint32(unix.NFNLGRP_NFTRACE))
	}

	go monitor.monitor()
	return monitor.eventCh, nil
}

func parseRuleFromMsg(msg netlink.Message) (*Rule, error) {
	genmsg := &NFGenMsg{}
	genmsg.Decode(msg.Data[:4])
	return ruleFromMsg(TableFamily(genmsg.NFGenFamily), msg)
}
