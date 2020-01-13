package nftables_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
)

func TestGetRule(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft list chain ip filter forward

	want := [][]byte{
		[]byte{0x2, 0x0, 0x0, 0x0, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xa, 0x0, 0x2, 0x0, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x0, 0x0, 0x0},
	}

	// The reply messages come from adding log.Printf("msgs: %#v", msgs) to
	// (*github.com/mdlayher/netlink/Conn).receive
	reply := [][]netlink.Message{
		nil,
		[]netlink.Message{netlink.Message{Header: netlink.Header{Length: 0x68, Type: 0xa06, Flags: 0x802, Sequence: 0x9acb0443, PID: 0xba38ef3c}, Data: []uint8{0x2, 0x0, 0x0, 0xc, 0xb, 0x0, 0x1, 0x0, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x0, 0xc, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x30, 0x0, 0x4, 0x0, 0x2c, 0x0, 0x1, 0x0, 0xc, 0x0, 0x1, 0x0, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x0, 0x1c, 0x0, 0x2, 0x0, 0xc, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6d, 0x92, 0x20, 0x20, 0xc, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x48, 0xd9}}},
		[]netlink.Message{netlink.Message{Header: netlink.Header{Length: 0x14, Type: 0x3, Flags: 0x2, Sequence: 0x9acb0443, PID: 0xba38ef3c}, Data: []uint8{0x0, 0x0, 0x0, 0x0}}},
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, reply),
	}

	rules, err := c.GetRule(
		&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		},
		&nftables.Chain{
			Name: "input",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(rules), 1; got != want {
		t.Fatalf("unexpected number of rules: got %d, want %d", got, want)
	}

	rule := rules[0]
	if got, want := len(rule.Exprs), 1; got != want {
		t.Fatalf("unexpected number of exprs: got %d, want %d", got, want)
	}

	ce, ok := rule.Exprs[0].(*expr.Counter)
	if !ok {
		t.Fatalf("unexpected expression type: got %T, want *expr.Counter", rule.Exprs[0])
	}

	if got, want := ce.Packets, uint64(674009); got != want {
		t.Errorf("unexpected number of packets: got %d, want %d", got, want)
	}

	if got, want := ce.Bytes, uint64(1838293024); got != want {
		t.Errorf("unexpected number of bytes: got %d, want %d", got, want)
	}
}

func TestDelRule(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft delete rule ipv4table ipv4chain-1 handle 9
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x31\x00\x0c\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x09"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.DelRule(&nftables.Rule{
		Table:  &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain:  &nftables.Chain{Name: "ipv4chain-1", Type: nftables.ChainTypeFilter},
		Handle: uint64(9),
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestAddRuleWithPosition(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add rule ip ipv4table ipv4chain-1 position 2 ip version 6
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x31\x00\xa8\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x01\x44\x00\x01\x80\x0c\x00\x01\x00\x62\x69\x74\x77\x69\x73\x65\x00\x34\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x0c\x00\x04\x80\x05\x00\x01\x00\xf0\x00\x00\x00\x0c\x00\x05\x80\x05\x00\x01\x00\x00\x00\x00\x00\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x60\x00\x00\x00\x0c\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x02"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.AddRule(&nftables.Rule{
		Position: 2,
		Table:    &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name:     "ipv4chain-1",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: 0,
		},

		Exprs: []expr.Any{
			// [ payload load 1b @ network header + 0 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       0, // Offset for a transport protocol header
				Len:          1, // 1 bytes for port
			},
			// [ bitwise reg 1 = (reg=1 & 0x000000f0 ) ^ 0x00000000 ]
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            1,
				Mask:           []byte{0xf0},
				Xor:            []byte{0x0},
			},
			// [ cmp eq reg 1 0x00000060 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{(0x6 << 4)},
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
