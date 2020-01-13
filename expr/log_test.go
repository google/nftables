package expr_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func TestLog(t *testing.T) {
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		//  nft add rule ipv4table ipv4chain-1  log prefix nftables
		[]byte("\x02\x00\x00\x00\x0e\x00\x01\x00\x69\x70\x76\x34\x74\x61\x62\x6c\x65\x00\x00\x00\x10\x00\x02\x00\x69\x70\x76\x34\x63\x68\x61\x69\x6e\x2d\x31\x00\x24\x00\x04\x80\x20\x00\x01\x80\x08\x00\x01\x00\x6c\x6f\x67\x00\x14\x00\x02\x80\x0d\x00\x02\x00\x6e\x66\x74\x61\x62\x6c\x65\x73\x00\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "ipv4table", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{Name: "ipv4chain-1", Type: nftables.ChainTypeFilter},
		Exprs: []expr.Any{
			&expr.Log{
				Key:  unix.NFTA_LOG_PREFIX,
				Data: []byte("nftables"),
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
