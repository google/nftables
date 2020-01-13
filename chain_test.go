package nftables_test

import (
	"testing"

	"github.com/google/nftables"
)

func TestAddChain(t *testing.T) {
	tests := []struct {
		name  string
		chain *nftables.Chain
		want  [][]byte
	}{
		{
			name: "Base chain",
			chain: &nftables.Chain{
				Name:     "base-chain",
				Hooknum:  nftables.ChainHookPrerouting,
				Priority: 0,
				Type:     nftables.ChainTypeFilter,
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter base-chain { type filter hook prerouting priority 0 \; }
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00\x14\x00\x04\x80\x08\x00\x01\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\x0b\x00\x07\x00\x66\x69\x6c\x74\x65\x72\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
		},
		{
			name: "Regular chain",
			chain: &nftables.Chain{
				Name: "regular-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft add table ip filter
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00"),
				// nft add chain ip filter regular-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x12\x00\x03\x00\x72\x65\x67\x75\x6c\x61\x72\x2d\x63\x68\x61\x69\x6e\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
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
		c.AddChain(tt.chain)
		if err := c.Flush(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDelChain(t *testing.T) {
	tests := []struct {
		name  string
		chain *nftables.Chain
		want  [][]byte
	}{
		{
			name: "Base chain",
			chain: &nftables.Chain{
				Name:     "base-chain",
				Hooknum:  nftables.ChainHookPrerouting,
				Priority: 0,
				Type:     nftables.ChainTypeFilter,
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft delete chain ip filter base-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0f\x00\x03\x00\x62\x61\x73\x65\x2d\x63\x68\x61\x69\x6e\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
		},
		{
			name: "Regular chain",
			chain: &nftables.Chain{
				Name: "regular-chain",
			},
			want: [][]byte{
				// batch begin
				[]byte("\x00\x00\x00\x0a"),
				// nft delete chain ip filter regular-chain
				[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x12\x00\x03\x00\x72\x65\x67\x75\x6c\x61\x72\x2d\x63\x68\x61\x69\x6e\x00\x00\x00"),
				// batch end
				[]byte("\x00\x00\x00\x0a"),
			},
		},
	}

	for _, tt := range tests {
		c := &nftables.Conn{
			TestDial: CheckNLReq(t, tt.want, nil),
		}

		tt.chain.Table = &nftables.Table{
			Family: nftables.TableFamilyIPv4,
			Name:   "filter",
		}
		c.DelChain(tt.chain)
		if err := c.Flush(); err != nil {
			t.Fatal(err)
		}
	}
}
