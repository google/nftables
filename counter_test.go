package nftables_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestAddCounter(t *testing.T) {
	// The want byte sequences come from stracing nft(8), e.g.:
	// strace -f -v -x -s 2048 -eraw=sendto nft add table ip nat
	//
	// The nft(8) command sequence was taken from:
	// https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)
	want := [][]byte{
		// batch begin
		[]byte("\x00\x00\x00\x0a"),
		// nft add counter ip filter fwded
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0a\x00\x02\x00\x66\x77\x64\x65\x64\x00\x00\x00\x08\x00\x03\x00\x00\x00\x00\x01\x1c\x00\x04\x80\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		// nft add rule ip filter forward counter name fwded
		[]byte("\x02\x00\x00\x00\x0b\x00\x01\x00\x66\x69\x6c\x74\x65\x72\x00\x00\x0c\x00\x02\x00\x66\x6f\x72\x77\x61\x72\x64\x00\x2c\x00\x04\x80\x28\x00\x01\x80\x0b\x00\x01\x00\x6f\x62\x6a\x72\x65\x66\x00\x00\x18\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x09\x00\x02\x00\x66\x77\x64\x65\x64\x00\x00\x00"),
		// batch end
		[]byte("\x00\x00\x00\x0a"),
	}

	c := &nftables.Conn{
		TestDial: CheckNLReq(t, want, nil),
	}

	c.AddObj(&nftables.CounterObj{
		Table:   &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Name:    "fwded",
		Bytes:   0,
		Packets: 0,
	})

	c.AddRule(&nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{Name: "forward", Type: nftables.ChainTypeFilter},
		Exprs: []expr.Any{
			&expr.Objref{
				Type: 1,
				Name: "fwded",
			},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}
