package expr_test

import (
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestConfigureRangePort(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule filter forward tcp sport != 2024-2030  return
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain filter forward '{' type filter hook forward priority 0 \; '}'
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule filter forward tcp sport != 2024-2030  return
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xf4\x00\x04\x80\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x10\x08\x00\x01\x00\x00\x00\x00\x01\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x00\x0c\x00\x03\x80\x05\x00\x01\x00\x06\x00\x00\x00\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x02\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x02\x3c\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x06\x00\x01\x00\x07\xe8\x00\x00\x0c\x00\x04\x80\x06\x00\x01\x00\x07\xee\x00\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.FlushRuleset()

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
			// [ payload load 2b @ transport header + 0 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0, // TODO
				Len:          2, // TODO
			},
			// [ range neq reg 1 0x0000e807 0x0000ee07 ]
			&expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 1,
				FromData: binaryutil.BigEndian.PutUint16(uint16(2024)),
				ToData:   binaryutil.BigEndian.PutUint16(uint16(2030)),
			},
			// [ immediate reg 0 return ]
			&expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureRangeIPv4(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule filter forward ip saddr != 192.168.1.0-192.168.2.0  return
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain filter forward '{' type filter hook forward priority 0 \; '}'
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule filter forward ip saddr != 192.168.1.0-192.168.2.0  return
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xa4\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00\x04\x00\x00\x00\x00\x04\x3c\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x2c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80\x08\x00\x01\x00\xc0\xa8\x01\x00\x0c\x00\x04\x80\x08\x00\x01\x00\xc0\xa8\x02\x00\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.FlushRuleset()

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

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // TODO
				Len:          4,  // TODO
			},
			// [ range neq reg 1 0x0000e807 0x0000ee07 ]
			&expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 1,
				FromData: net.ParseIP("192.168.1.0").To4(),
				ToData:   net.ParseIP("192.168.2.0").To4(),
			},
			// [ immediate reg 0 return ]
			&expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureRangeIPv6(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add rule ip6 filter forward ip6 saddr != 2001:0001::1-2001:0002::1 return
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Tcp
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft flush ruleset
		[]byte("\x00\x00\x00\x00"),
		// nft add table ip6 filter
		[]byte("\x0a\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip6 filter forward '{' type filter hook forward priority 0 \; '}'
		[]byte("\x0a\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x03\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x02\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip6 filter forward ip6 saddr != 2001:0001::1-2001:0002::1 return
		[]byte("\x0a\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\xbc\x00\x04\x80\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x08\x08\x00\x04\x00\x00\x00\x00\x10\x54\x00\x01\x80\x0a\x00\x01\x00\x72\x61\x6e\x67\x65\x00\x00\x00\x44\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x18\x00\x03\x80\x14\x00\x01\x00\x20\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x18\x00\x04\x80\x14\x00\x01\x00\x20\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x1c\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x10\x00\x02\x80\x0c\x00\x02\x80\x08\x00\x01\x00\xff\xff\xff\xfb"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.FlushRuleset()

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   "filter",
	})

	forward := c.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	ip1 := net.ParseIP("2001:0001::1").To16()
	ip2 := net.ParseIP("2001:0002::1").To16()

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			// [ payload load 16b @ network header + 8 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       8,  // TODO
				Len:          16, // TODO
			},
			// [ range neq reg 1 0x01000120 0x00000000 0x00000000 0x01000000 0x02000120 0x00000000 0x00000000 0x01000000 ]
			&expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 1,
				FromData: ip1,
				ToData:   ip2,
			},
			// [ immediate reg 0 return ]
			&expr.Verdict{
				Kind: expr.VerdictKind(unix.NFT_RETURN),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
