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
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"syscall"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

// A Conn represents a netlink connection of the nftables family.
//
// All methods return their input, so that variables can be defined from string
// literals when desired.
//
// Commands are buffered. Flush sends all buffered commands in a single batch.
type Conn struct {
	TestDial nltest.Func // for testing only; passed to nltest.Dial
	NetNS    int         // fd referencing the network namespace netlink will interact with.

	lasting      bool       // establish a lasting connection to be used across multiple netlink operations.
	mu           sync.Mutex // protects the following state
	messages     []netlinkMessage
	err          error
	nlconn       *netlink.Conn // netlink socket using NETLINK_NETFILTER protocol.
	sockOptions  []SockOption
	lastID       uint32
	allocatedIDs uint32
}

type netlinkMessage struct {
	Header netlink.Header
	Data   []byte
	rule   *Rule
}

// ConnOption is an option to change the behavior of the nftables Conn returned by Open.
type ConnOption func(*Conn)

// SockOption is an option to change the behavior of the netlink socket used by the nftables Conn.
type SockOption func(*netlink.Conn) error

// New returns a netlink connection for querying and modifying nftables. Some
// aspects of the new netlink connection can be configured using the options
// WithNetNSFd, WithTestDial, and AsLasting.
//
// A lasting netlink connection should be closed by calling CloseLasting() to
// close the underlying lasting netlink connection, cancelling all pending
// operations using this connection.
func New(opts ...ConnOption) (*Conn, error) {
	cc := &Conn{}
	for _, opt := range opts {
		opt(cc)
	}

	if !cc.lasting {
		return cc, nil
	}

	nlconn, err := cc.dialNetlink()
	if err != nil {
		return nil, err
	}
	cc.nlconn = nlconn
	return cc, nil
}

// AsLasting creates the new netlink connection as a lasting connection that is
// reused across multiple netlink operations, instead of opening and closing the
// underlying netlink connection only for the duration of a single netlink
// operation.
func AsLasting() ConnOption {
	return func(cc *Conn) {
		// We cannot create the underlying connection yet, as we are called
		// anywhere in the option processing chain and there might be later
		// options still modifying connection behavior.
		cc.lasting = true
	}
}

// WithNetNSFd sets the network namespace to create a new netlink connection to:
// the fd must reference a network namespace.
func WithNetNSFd(fd int) ConnOption {
	return func(cc *Conn) {
		cc.NetNS = fd
	}
}

// WithTestDial sets the specified nltest.Func when creating a new netlink
// connection.
func WithTestDial(f nltest.Func) ConnOption {
	return func(cc *Conn) {
		cc.TestDial = f
	}
}

// WithSockOptions sets the specified socket options when creating a new netlink
// connection.
func WithSockOptions(opts ...SockOption) ConnOption {
	return func(cc *Conn) {
		cc.sockOptions = append(cc.sockOptions, opts...)
	}
}

// netlinkCloser is returned by netlinkConn(UnderLock) and must be called after
// being done with the returned netlink connection in order to properly close
// this connection, if necessary.
type netlinkCloser func() error

// netlinkConn returns a netlink connection together with a netlinkCloser that
// later must be called by the caller when it doesn't need the returned netlink
// connection anymore. The netlinkCloser will close the netlink connection when
// necessary. If New has been told to create a lasting connection, then this
// lasting netlink connection will be returned, otherwise a new "transient"
// netlink connection will be opened and returned instead. netlinkConn must not
// be called while the Conn.mu lock is currently helt (this will cause a
// deadlock). Use netlinkConnUnderLock instead in such situations.
func (cc *Conn) netlinkConn() (*netlink.Conn, netlinkCloser, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.netlinkConnUnderLock()
}

// netlinkConnUnderLock works like netlinkConn but must be called while holding
// the Conn.mu lock.
func (cc *Conn) netlinkConnUnderLock() (*netlink.Conn, netlinkCloser, error) {
	if cc.nlconn != nil {
		return cc.nlconn, func() error { return nil }, nil
	}
	nlconn, err := cc.dialNetlink()
	if err != nil {
		return nil, nil, err
	}
	return nlconn, func() error { return nlconn.Close() }, nil
}

func receiveAckAware(nlconn *netlink.Conn, sentMsgFlags netlink.HeaderFlags) ([]netlink.Message, error) {
	if nlconn == nil {
		return nil, errors.New("netlink conn is not initialized")
	}

	// first receive will be the message that we expect
	reply, err := nlconn.Receive()
	if err != nil {
		return nil, err
	}

	if (sentMsgFlags & netlink.Acknowledge) == 0 {
		// we did not request an ack
		return reply, nil
	}

	if (sentMsgFlags & netlink.Dump) == netlink.Dump {
		// sent message has Dump flag set, there will be no acks
		// https://github.com/torvalds/linux/blob/7e062cda7d90543ac8c7700fc7c5527d0c0f22ad/net/netlink/af_netlink.c#L2387-L2390
		return reply, nil
	}

	// Now we expect an ack
	ack, err := nlconn.Receive()
	if err != nil {
		return nil, err
	}

	if len(ack) == 0 {
		return nil, errors.New("received an empty ack")
	}

	msg := ack[0]
	if msg.Header.Type != netlink.Error {
		// acks should be delivered as NLMSG_ERROR
		return nil, fmt.Errorf("expected header %v, but got %v", netlink.Error, msg.Header.Type)
	}

	if binaryutil.BigEndian.Uint32(msg.Data[:4]) != 0 {
		// if errno field is not set to 0 (success), this is an error
		return nil, fmt.Errorf("error delivered in message: %v", msg.Data)
	}

	return reply, nil
}

// CloseLasting closes the lasting netlink connection that has been opened using
// AsLasting option when creating this connection. If either no lasting netlink
// connection has been opened or the lasting connection is already in the
// process of closing or has been closed, CloseLasting will immediately return
// without any error.
//
// CloseLasting will terminate all pending netlink operations using the lasting
// connection.
//
// After closing a lasting connection, the connection will revert to using
// on-demand transient netlink connections when calling further netlink
// operations (such as GetTables).
func (cc *Conn) CloseLasting() error {
	// Don't acquire the lock for the whole duration of the CloseLasting
	// operation, but instead only so long as to make sure to only run the
	// netlink socket close on the first time with a lasting netlink socket. As
	// there is only the New() constructor, but no Open() method, it's
	// impossible to reopen a lasting connection.
	cc.mu.Lock()
	nlconn := cc.nlconn
	cc.nlconn = nil
	cc.mu.Unlock()
	if nlconn != nil {
		return nlconn.Close()
	}
	return nil
}

// Flush sends all buffered commands in a single batch to nftables.
func (cc *Conn) Flush() error {
	cc.mu.Lock()
	defer func() {
		cc.messages = nil
		cc.allocatedIDs = 0
		cc.mu.Unlock()
	}()
	if len(cc.messages) == 0 {
		// Messages were already programmed, returning nil
		return nil
	}
	if cc.err != nil {
		return cc.err // serialization error
	}
	conn, closer, err := cc.netlinkConnUnderLock()
	if err != nil {
		return err
	}
	defer func() { _ = closer() }()

	err = cc.setWriteBuffer(conn)
	if err != nil {
		return err
	}
	err = cc.setReadBuffer(conn)
	if err != nil {
		return err
	}

	messages, err := conn.SendMessages(batch(cc.messages))
	if err != nil {
		return fmt.Errorf("SendMessages: %w", err)
	}

	var errs error

	// Fetch replies. Each message with the Echo flag triggers a reply of the same
	// type. Additionally, if the first message of the batch has the Echo flag, we
	// get a reply of type NFT_MSG_NEWGEN, which we ignore.
	replyIndex := 0
	for replyIndex < len(cc.messages) && cc.messages[replyIndex].Header.Flags&netlink.Echo == 0 {
		replyIndex++
	}
	replies, err := conn.Receive()
	for err == nil && len(replies) != 0 {
		reply := replies[0]
		if reply.Header.Type == netlink.Error && reply.Header.Sequence == messages[1].Header.Sequence {
			// The next message is the acknowledgement for the first message in the
			// batch; stop looking for replies.
			break
		} else if replyIndex < len(cc.messages) {
			msg := messages[replyIndex+1]
			if msg.Header.Sequence == reply.Header.Sequence && msg.Header.Type == reply.Header.Type {
				// The only messages which set the echo flag are rule create messages.
				err := cc.messages[replyIndex].rule.handleCreateReply(reply)
				if err != nil {
					errs = errors.Join(errs, err)
				}
				replyIndex++
				for replyIndex < len(cc.messages) && cc.messages[replyIndex].Header.Flags&netlink.Echo == 0 {
					replyIndex++
				}
			}
		}
		replies = replies[1:]
		if len(replies) == 0 {
			replies, err = conn.Receive()
		}
	}

	// Fetch the requested acknowledgement for each message we sent.
	for i := range cc.messages {
		if i != 0 {
			_, err = conn.Receive()
		}
		if err != nil {
			if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) {
				// Kernel will only send one error to user space.
				return err
			}
			errs = errors.Join(errs, err)
		}
	}

	if errs != nil {
		return fmt.Errorf("conn.Receive: %w", errs)
	}
	if replyIndex < len(cc.messages) {
		return fmt.Errorf("missing reply for message %d in batch", replyIndex)
	}

	return nil
}

// FlushRuleset flushes the entire ruleset. See also
// https://wiki.nftables.org/wiki-nftables/index.php/Operations_at_ruleset_level
func (cc *Conn) FlushRuleset() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.messages = append(cc.messages, netlinkMessage{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_DELTABLE),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create,
		},
		Data: extraHeader(0, 0),
	})
}

func (cc *Conn) dialNetlink() (*netlink.Conn, error) {
	var (
		conn *netlink.Conn
		err  error
	)

	if cc.TestDial != nil {
		conn = nltest.Dial(cc.TestDial)
	} else {
		conn, err = netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: cc.NetNS})
	}

	if err != nil {
		return nil, err
	}

	for _, opt := range cc.sockOptions {
		if err := opt(conn); err != nil {
			return nil, err
		}
	}

	return conn, nil
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

func (cc *Conn) marshalExpr(fam byte, e expr.Any) []byte {
	b, err := expr.Marshal(fam, e)
	if err != nil {
		cc.setErr(err)
		return nil
	}
	return b
}

func batch(messages []netlinkMessage) []netlink.Message {
	batch := make([]netlink.Message, len(messages)+2)
	batch[0] = netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_BEGIN),
			Flags: netlink.Request,
		},
		Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
	}

	for i, msg := range messages {
		batch[i+1] = netlink.Message{
			Header: msg.Header,
			Data:   msg.Data,
		}
	}

	batch[len(messages)+1] = netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_MSG_BATCH_END),
			Flags: netlink.Request,
		},
		Data: extraHeader(0, unix.NFNL_SUBSYS_NFTABLES),
	}

	return batch
}

// allocateTransactionID allocates an identifier which is only valid in the
// current transaction.
func (cc *Conn) allocateTransactionID() uint32 {
	if cc.allocatedIDs == math.MaxUint32 {
		panic(fmt.Sprintf("trying to allocate more than %d IDs in a single nftables transaction", math.MaxUint32))
	}
	// To make it more likely to catch when a transaction ID is erroneously used
	// in a later transaction, cc.lastID is not reset after each transaction;
	// instead it is only reset once it rolls over from math.MaxUint32 to 0.
	cc.allocatedIDs++
	cc.lastID++
	if cc.lastID == 0 {
		cc.lastID = 1
	}
	return cc.lastID
}

// getMessageSize returns the total size of all messages in the buffer.
func (cc *Conn) getMessageSize() int {
	var total int
	for _, msg := range cc.messages {
		total += len(msg.Data) + 16 // 16 bytes for the header
	}
	return total
}

// setWriteBuffer automatically sets the write buffer of the given connection to
// the accumulated message size. This is only done if the current write buffer
// is smaller than the message size.
//
// nftables actually handles this differently, it multiplies the number of
// iovec entries by 2MB. This is not possible to do here as our underlying
// netlink and socket libraries will only add a single iovec entry and
// won't expose the number of entries.
// https://git.netfilter.org/nftables/tree/src/mnl.c?id=713592c6008a8c589a00d3d3d2e49709ff2de62c#n262
//
// TODO: Update this function to mimic the behavior of nftables once those
// limitations are no longer present.
func (cc *Conn) setWriteBuffer(conn *netlink.Conn) error {
	messageSize := cc.getMessageSize()
	writeBuffer, err := conn.WriteBuffer()
	if err != nil {
		return err
	}
	if writeBuffer < messageSize {
		return conn.SetWriteBuffer(messageSize)
	}

	return nil
}

// getDefaultEchoReadBuffer returns the minimum read buffer size for batches
// with echo messages.
//
// See https://git.netfilter.org/libmnl/tree/include/libmnl/libmnl.h?id=03da98bcd284d55212bc79e91dfb63da0ef7b937#n20
// and https://git.netfilter.org/nftables/tree/src/mnl.c?id=713592c6008a8c589a00d3d3d2e49709ff2de62c#n391
func (cc *Conn) getDefaultEchoReadBuffer() int {
	pageSize := os.Getpagesize()
	if pageSize < 8192 {
		return pageSize * 1024
	}

	return 8192 * 1024
}

// setReadBuffer  automatically sets the read buffer of the given connection
// to the required size. This is only done if the current read buffer is smaller
// than the required size.
//
// See https://git.netfilter.org/nftables/tree/src/mnl.c?id=713592c6008a8c589a00d3d3d2e49709ff2de62c#n426
func (cc *Conn) setReadBuffer(conn *netlink.Conn) error {
	var bufferSize int

	// If there are any messages with the Echo flag, we initialize the buffer size
	// to the default echo read buffer size.
	for _, msg := range cc.messages {
		if msg.Header.Flags&netlink.Echo == 0 {
			bufferSize = cc.getDefaultEchoReadBuffer()
			break
		}
	}

	// Just like nftables, we allocate 1024 bytes for each message in the batch.
	requiredSize := len(cc.messages) * 1024
	if bufferSize < requiredSize {
		bufferSize = requiredSize
	}

	currSize, err := conn.ReadBuffer()
	if err != nil {
		return err
	}
	if currSize < bufferSize {
		return conn.SetReadBuffer(bufferSize)
	}
	return nil
}
