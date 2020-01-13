package expr_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestReject(t *testing.T) {
	tests := []struct {
		name        string
		chain       *nftables.Chain
		want        [][]byte
		rejectExprs []expr.Any
	}{
		{
			name: "Reject",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain reject
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			rejectExprs: []expr.Any{
				&expr.Reject{},
			},
		},
		{
			name: "Reject with tcp reset",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain reject with tcp reset
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x05\x00\x02\x00\x01\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			rejectExprs: []expr.Any{
				&expr.Reject{Type: unix.NFT_REJECT_TCP_RST, Code: unix.NFT_REJECT_TCP_RST},
			},
		},
		{
			name: "Reject with icmp type host-unreachable",
			chain: &nftables.Chain{
				Name: "base-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip  filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// nft add  rule ip filter base-chain reject with icmp type host-unreachable
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x28\x00\x04\x80\x24\x00\x01\x80\x0b\x00\x01\x00\x72\x65\x6a\x65\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			rejectExprs: []expr.Any{
				&expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: unix.NFT_REJECT_ICMP_UNREACH},
			},
		},
	}

	for _, tt := range tests {
		c := &nftables.Conn{
			TestDial: CheckNLReq(t, tt.want, nil),
		}

		filter := c.AddTable(&nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		})

		tt.chain.Table = filter
		chain := c.AddChain(tt.chain)
		c.AddRule(&nftables.Rule{
			Table: filter,
			Chain: chain,
			Exprs: tt.rejectExprs,
		})
		if err := c.Flush(); err != nil {
			t.Fatalf("Test \"%s\" failed with error: %+v", tt.name, err)
		}
	}
}