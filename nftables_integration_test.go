package nftables_test

import (
	"bytes"
	"net"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestFlushTable(t *testing.T) {
	if os.Getenv("TRAVIS") == "true" {
		t.SkipNow()
	}
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	nat := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	forward := c.AddChain(&nftables.Chain{
		Table: filter,
		Name:  "forward",
	})

	input := c.AddChain(&nftables.Chain{
		Table: filter,
		Name:  "input",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Table: nat,
		Name:  "prerouting",
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ cmp eq reg 1 0x0000d204 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x04, 0xd2},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ cmp eq reg 1 0x000010e1 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0xe1, 0x10},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ cmp eq reg 1 0x0000162e ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x2e, 0x16},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: prerouting,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // TODO
				Len:          2, // TODO
			},
			// [ cmp eq reg 1 0x00001600 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x00, 0x16},
			},

			// [ immediate reg 1 0x0000ae08 ]
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(2222),
			},

			// [ redir proto_min reg 1 ]
			&expr.Redir{
				RegisterProtoMin: 1,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}
	rules, err := c.GetRule(filter, forward)
	if err != nil {
		t.Errorf("c.GetRule() failed: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}
	rules, err = c.GetRule(filter, input)
	if err != nil {
		t.Errorf("c.GetRule() failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}
	rules, err = c.GetRule(nat, prerouting)
	if err != nil {
		t.Errorf("c.GetRule() failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}

	c.FlushTable(filter)

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	rules, err = c.GetRule(filter, forward)
	if err != nil {
		t.Errorf("c.GetRule() failed: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
	rules, err = c.GetRule(filter, input)
	if err != nil {
		t.Errorf("c.GetRule() failed: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
	rules, err = c.GetRule(nat, prerouting)
	if err != nil {
		t.Errorf("c.GetRule() failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}
}

func TestFlushChain(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	forward := c.AddChain(&nftables.Chain{
		Table: filter,
		Name:  "forward",
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ cmp eq reg 1 0x0000d204 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x04, 0xd2},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},

			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ cmp eq reg 1 0x000010e1 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0xe1, 0x10},
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}
	rules, err := c.GetRule(filter, forward)
	if err != nil {
		t.Errorf("c.GetRule() failed: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}

	c.FlushChain(forward)

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	rules, err = c.GetRule(filter, forward)
	if err != nil {
		t.Errorf("c.GetRule() failed: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
}

func TestGetRuleLookupVerdictImmediate(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	forward := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	set := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(set, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000006 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ lookup reg 1 set __set%d ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        set.Name,
				SetID:          set.ID,
			},
			// [ immediate reg 0 drop ]
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
			// [ immediate reg 2 kek ]
			&expr.Immediate{
				Register: 2,
				Data:     []byte("kek"),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRule(
		&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		},
		&nftables.Chain{
			Name: "forward",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}
	if got, want := len(rules[0].Exprs), 6; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	lookup, lookupOk := rules[0].Exprs[3].(*expr.Lookup)
	if !lookupOk {
		t.Fatalf("Exprs[3] is type %T, want *expr.Lookup", rules[0].Exprs[3])
	}
	if want := (&expr.Lookup{
		SourceRegister: 1,
		SetName:        set.Name,
	}); !reflect.DeepEqual(lookup, want) {
		t.Errorf("lookup expr = %+v, wanted %+v", lookup, want)
	}

	verdict, verdictOk := rules[0].Exprs[4].(*expr.Verdict)
	if !verdictOk {
		t.Fatalf("Exprs[4] is type %T, want *expr.Verdict", rules[0].Exprs[4])
	}
	if want := (&expr.Verdict{
		Kind: expr.VerdictAccept,
	}); !reflect.DeepEqual(verdict, want) {
		t.Errorf("verdict expr = %+v, wanted %+v", verdict, want)
	}

	imm, immOk := rules[0].Exprs[5].(*expr.Immediate)
	if !immOk {
		t.Fatalf("Exprs[4] is type %T, want *expr.Immediate", rules[0].Exprs[5])
	}
	if want := (&expr.Immediate{
		Register: 2,
		Data:     []byte("kek"),
	}); !reflect.DeepEqual(imm, want) {
		t.Errorf("verdict expr = %+v, wanted %+v", imm, want)
	}
}

func TestCreateUseNamedSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.SetAddElements(portSet, []nftables.SetElement{{Key: binaryutil.BigEndian.PutUint16(22)}}); err != nil {
		t.Errorf("c.SetVal(portSet) failed: %v", err)
	}

	ipSet := &nftables.Set{
		Table:   filter,
		Name:    "IPs_4_dayz",
		KeyType: nftables.TypeIPAddr,
	}
	if err := c.AddSet(ipSet, []nftables.SetElement{{Key: []byte(net.ParseIP("192.168.1.64").To4())}}); err != nil {
		t.Errorf("c.AddSet(ipSet) failed: %v", err)
	}
	if err := c.SetAddElements(ipSet, []nftables.SetElement{{Key: []byte(net.ParseIP("192.168.1.42").To4())}}); err != nil {
		t.Errorf("c.SetVal(ipSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	sets, err := c.GetSets(filter)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(sets) != 2 {
		t.Fatalf("len(sets) = %d, want 2", len(sets))
	}
	if sets[0].Name != "kek" {
		t.Errorf("set[0].Name = %q, want kek", sets[0].Name)
	}
	if sets[1].Name != "IPs_4_dayz" {
		t.Errorf("set[1].Name = %q, want IPs_4_dayz", sets[1].Name)
	}
}

func TestCreateDeleteNamedSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, nil); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	c.DelSet(portSet)

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	sets, err := c.GetSets(filter)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(sets) != 0 {
		t.Fatalf("len(sets) = %d, want 0", len(sets))
	}
}

func TestDeleteElementNamedSet(t *testing.T) {
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, []nftables.SetElement{{Key: []byte{0, 22}}, {Key: []byte{0, 23}}}); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	c.SetDeleteElements(portSet, []nftables.SetElement{{Key: []byte{0, 23}}})

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	elems, err := c.GetSetElements(portSet)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(elems) != 1 {
		t.Fatalf("len(elems) = %d, want 1", len(elems))
	}
	if !bytes.Equal(elems[0].Key, []byte{0, 22}) {
		t.Errorf("elems[0].Key = %v, want 22", elems[0].Key)
	}
}

func TestFlushNamedSet(t *testing.T) {
	if os.Getenv("TRAVIS") == "true" {
		t.SkipNow()
	}
	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := openSystemNFTConn(t)
	defer cleanupSystemNFTConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})

	portSet := &nftables.Set{
		Table:   filter,
		Name:    "kek",
		KeyType: nftables.TypeInetService,
	}
	if err := c.AddSet(portSet, []nftables.SetElement{{Key: []byte{0, 22}}, {Key: []byte{0, 23}}}); err != nil {
		t.Errorf("c.AddSet(portSet) failed: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Errorf("c.Flush() failed: %v", err)
	}

	c.FlushSet(portSet)

	if err := c.Flush(); err != nil {
		t.Errorf("Second c.Flush() failed: %v", err)
	}

	elems, err := c.GetSetElements(portSet)
	if err != nil {
		t.Errorf("c.GetSets() failed: %v", err)
	}
	if len(elems) != 0 {
		t.Fatalf("len(elems) = %d, want 0", len(elems))
	}
}

// openSystemNFTConn returns a netlink connection that tests against
// the running kernel in a separate network namespace.
// cleanupSystemNFTConn() must be called from a defer to cleanup
// created network namespace.
func openSystemNFTConn(t *testing.T) (*nftables.Conn, netns.NsHandle) {
	t.Helper()
	if !*enableSysTests {
		t.SkipNow()
	}
	// We lock the goroutine into the current thread, as namespace operations
	// such as those invoked by `netns.New()` are thread-local. This is undone
	// in cleanupSystemNFTConn().
	runtime.LockOSThread()

	ns, err := netns.New()
	if err != nil {
		t.Fatalf("netns.New() failed: %v", err)
	}
	return &nftables.Conn{NetNS: int(ns)}, ns
}

func cleanupSystemNFTConn(t *testing.T, newNS netns.NsHandle) {
	defer runtime.UnlockOSThread()

	if err := newNS.Close(); err != nil {
		t.Fatalf("newNS.Close() failed: %v", err)
	}
}
