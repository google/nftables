package expr_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestCt(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// sudo nft add rule ipv4table ipv4chain-5 ct mark 123 counter
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x35\x00\x24\x00\x04\x80\x20\x00\x01\x80\x07\x00\x01\x00\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x01\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name: "ipv4chain-5",
		},
		Exprs: []expr.Any{
			//	[ ct load mark => reg 1 ]
			&expr.Ct{
				Key:      unix.NFT_CT_MARK,
				Register: 1,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestCtSet(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// sudo nft add rule filter forward ct mark set 1
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x50\x00\x04\x80\x2c\x00\x01\x80\x0e\x00\x01\x00\x69\x6d\x6d\x65\x64\x69\x61\x74\x65\x00\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x0c\x00\x02\x80\x08\x00\x01\x00\x01\x00\x00\x00\x20\x00\x01\x80\x07\x00\x01\x00\x63\x74\x00\x00\x14\x00\x02\x80\x08\x00\x02\x00\x00\x00\x00\x03\x08\x00\x04\x00\x00\x00\x00\x01"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name: "forward",
		},
		Exprs: []expr.Any{
			//	[ immediate reg 1 0x00000001 ]
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(1),
			},
			// [ ct set mark with reg 1 ]
			&expr.Ct{
				Key:            expr.CtKeyMARK,
				Register:       1,
				SourceRegister: true,
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
