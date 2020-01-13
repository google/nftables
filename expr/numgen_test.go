package expr_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestNumgen(t *testing.T) {
	tests := []struct {
		name        string
		chain       *nftables.Chain
		want        [][]byte
		numgenExprs []expr.Any
	}{
		{
			name: "numgen random",
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
				// nft add rule ip filter base-chain numgen random mod 1  offset 0 vmap { 0 : drop }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x38\x00\x04\x80\x34\x00\x01\x80\x0b\x00\x01\x00\x6e\x75\x6d\x67\x65\x6e\x00\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x01\x08\x00\x04\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			numgenExprs: []expr.Any{
				&expr.Numgen{
					Register: 1,
					Type:     unix.NFT_NG_RANDOM,
					Modulus:  0x1,
					Offset:   0,
				},
			},
		},
		{
			name: "numgen incremental",
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
				// nft add rule ip filter base-chain numgen inc mod 1  offset 0 vmap { 0 : drop }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x02\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x38\x00\x04\x80\x34\x00\x01\x80\x0b\x00\x01\x00\x6e\x75\x6d\x67\x65\x6e\x00\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x00\x08\x00\x04\x00\x00\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
			numgenExprs: []expr.Any{
				&expr.Numgen{
					Register: 1,
					Type:     unix.NFT_NG_INCREMENTAL,
					Modulus:  0x1,
					Offset:   0,
				},
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
			Exprs: tt.numgenExprs,
		})
		if err := c.Flush(); err != nil {
			t.Fatalf("Test \"%s\" failed with error: %+v", tt.name, err)
		}
	}
}
