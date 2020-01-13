package expr_test

import (
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestStatelessNAT(t *testing.T) {
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
		// nft add table ip filter
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
		// nft add chain ip filter base-chain { type filter hook prerouting priority 0 \; }
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
		// nft add rule ip filter base-chain ip daddr set 192.168.1.1 notrack
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x8c\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\xc0\xa8\x01\x01\x4c\x00\x01\x80\x0c\x00\x01\x00\x70\x61\x79\x6c\x6f\x61\x64\x00\x3c\x00\x02\x80\x08\x00\x05\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x10\x08\x00\x04\x00\x00\x00\x00\x04\x08\x00\x06\x00\x00\x00\x00\x01\x08\x00\x07\x00\x00\x00\x00\x0a\x08\x00\x08\x00\x00\x00\x00\x01\x10\x00\x01\x80\x0c\x00\x01\x00\x6e\x6f\x74\x72\x61\x63\x6b\x00"),
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
		Name:     "base-chain",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: forward,
		Exprs: []expr.Any{
			&expr.Immediate{
				Register: 1,
				Data:     net.ParseIP("192.168.1.1").To4(),
			},
			// [ payload write reg 1 => 4b @ network header + 16 csum_type 1 csum_off 10 csum_flags 0x1 ]
			&expr.Payload{
				OperationType:  expr.PayloadWrite,
				SourceRegister: 1,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         16,
				Len:            4,
				CsumType:       expr.CsumTypeInet,
				CsumOffset:     10,
				CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
			},
			// [ notrack ]
			&expr.Notrack{},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
