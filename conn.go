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
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

type Entity interface {
	HandleResponse(netlink.Message)
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
	sync.Mutex
	put      sync.Mutex
	messages []netlink.Message
	entities map[int32]Entity
	it       int32
	err      error
}

// Flush sends all buffered commands in a single batch to nftables.
func (cc *Conn) Flush() error {
	cc.Lock()
	defer func() {
		cc.messages = nil
		cc.entities = nil
		cc.it = 0
		cc.Unlock()
	}()
	if len(cc.messages) == 0 {
		// Messages were already programmed, returning nil
		return nil
	}
	if cc.err != nil {
		return cc.err // serialization error
	}
	conn, err := cc.dialNetlink()
	if err != nil {
		return err
	}

	defer conn.Close()

	cc.endBatch(cc.messages)

	_, err = conn.SendMessages(cc.messages[:cc.it+1])

	if err != nil {
		return fmt.Errorf("SendMessages: %w", err)
	}

	// Retrieving of seq number associated to entities
	entitiesBySeq := make(map[uint32]Entity)
	for i, e := range cc.entities {
		entitiesBySeq[cc.messages[i].Header.Sequence] = e
	}

	// Trigger entities callback
	msg, err := cc.checkReceive(conn)
	for msg {
		rmsg, err := conn.Receive()

		if err != nil {
			return fmt.Errorf("Receive: %w", err)
		}

		for _, msg := range rmsg {
			if e, ok := entitiesBySeq[msg.Header.Sequence]; ok {
				e.HandleResponse(msg)
			}
		}
		msg, err = cc.checkReceive(conn)
	}

	return err
}

// PutMessage store netlink message to sent after
func (cc *Conn) PutMessage(msg netlink.Message) int32 {
	cc.put.Lock()
	defer cc.put.Unlock()

	if cc.messages == nil {
		cc.messages = make([]netlink.Message, 16)
		cc.messages[0] = netlink.Message{
			Header: netlink.Header{
				Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_BEGIN),
				Flags: netlink.Request,
			},
			Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
		}
	}

	i := atomic.AddInt32(&cc.it, 1)

	if len(cc.messages) <= int(i) {
		cc.messages = resize(cc.messages)
	}

	cc.messages[i] = msg

	return i
}

// PutEntity store entity to relate to netlink response
func (cc *Conn) PutEntity(i int32, e Entity) {
	if cc.entities == nil {
		cc.entities = make(map[int32]Entity)
	}
	cc.entities[i] = e
}

func (cc *Conn) checkReceive(c *netlink.Conn) (bool, error) {
	if cc.TestDial != nil {
		return false, nil
	}

	sc, err := c.SyscallConn()

	if err != nil {
		return false, fmt.Errorf("SyscallConn error: %w", err)
	}

	var n int

	sc.Control(func(fd uintptr) {
		var fdSet unix.FdSet
		fdSet.Zero()
		fdSet.Set(int(fd))

		n, err = unix.Select(int(fd)+1, &fdSet, nil, nil, &unix.Timeval{})
	})

	if err == nil && n > 0 {
		return true, nil
	}

	return false, err
}

// FlushRuleset flushes the entire ruleset. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Operations_at_ruleset_level
func (cc *Conn) FlushRuleset() {
	cc.Lock()
	defer cc.Unlock()
	cc.PutMessage(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELTABLE),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: extraHeader(0, 0),
	})
}

func (cc *Conn) dialNetlink() (*netlink.Conn, error) {
	if cc.TestDial != nil {
		return nltest.Dial(cc.TestDial), nil
	}
	return netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: cc.NetNS})
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

func (cc *Conn) endBatch(messages []netlink.Message) {

	i := atomic.AddInt32(&cc.it, 1)

	if len(cc.messages) <= int(i) {
		cc.messages = resize(cc.messages)
	}

	cc.messages[i] = netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_END),
			Flags: netlink.Request,
		},
		Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
	}
}

func resize(messages []netlink.Message) []netlink.Message {
	new := make([]netlink.Message, cap(messages)*2)
	copy(new, messages)
	return new
}
