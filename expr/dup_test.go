package expr_test

import (
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func TestDup(t *testing.T) {

	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule filter prerouting mark set jhash ip saddr mod 2
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),

		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),

		// nft add table ip mangle
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),

		// nft add chain ip mangle base-chain { type filter hook prerouting priority 0 \; }
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),

		// nft add rule mangle base-chain dup to 127.0.0.50 device lo
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x7c\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x7f\x00\x00\x32\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x02\x0c\x00\x02\x80\x08\x00\x01\x00\x01\x00\x00\x00\x20\x00\x01\x80\x08\x00\x01\x00\x64\x75\x70\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02"),

		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.FlushRuleset()

	mangle := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "mangle",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Name:     "base-chain",
		Table:    mangle,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	lo, err := net.InterfaceByName("lo")

	if err != nil {
		t.Fatal(err)
	}

	c.AddRule(&nftables.Rule{
		Table: mangle,
		Chain: prerouting,
		Exprs: []expr.Any{
			// [ immediate reg 1 0x3200007f ]
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("127.0.0.50").To4(),
			},
			// [ immediate reg 2 0x00000001 ]
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.NativeEndian.PutUint32(uint32(lo.Index)),
			},
			// [ dup sreg_addr 1 sreg_dev 2 ]
			&expr.Dup{
				RegAddr:     1,
				RegDev:      2,
				IsRegDevSet: true,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestDupWoDev(t *testing.T) {

	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule filter prerouting mark set jhash ip saddr mod 2
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),

		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),

		// nft add table ip mangle
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),

		// nft add chain ip mangle base-chain { type filter hook prerouting priority 0 \; }
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),

		// nft add rule mangle base-chain dup to 127.0.0.50
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x6d\x61\x6e\x67\x6c\x65\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x48\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x7f\x00\x00\x32\x18\x00\x01\x80\x08\x00\x01\x00\x64\x75\x70\x00\x0c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"),

		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.FlushRuleset()

	mangle := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "mangle",
	})

	prerouting := c.AddChain(&nftables.Chain{
		Name:     "base-chain",
		Table:    mangle,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: mangle,
		Chain: prerouting,
		Exprs: []expr.Any{
			// [ immediate reg 1 0x3200007f ]
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("127.0.0.50").To4(),
			},
			// [ dup sreg_addr 1 sreg_dev 2 ]
			&expr.Dup{
				RegAddr:     1,
				IsRegDevSet: false,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
