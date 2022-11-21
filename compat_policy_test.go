package nftables

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"golang.org/x/sys/unix"
)

func TestGetCompatPolicy(t *testing.T) {
	// -tcp --dport 0:65534 --sport 0:65534
	tcpMatch := &expr.Match{
		Name: "tcp",
		Info: &xt.Tcp{
			SrcPorts: [2]uint16{0, 65534},
			DstPorts: [2]uint16{0, 65534},
		},
	}

	// -udp --dport 0:65534 --sport 0:65534
	udpMatch := &expr.Match{
		Name: "udp",
		Info: &xt.Udp{
			SrcPorts: [2]uint16{0, 65534},
			DstPorts: [2]uint16{0, 65534},
		},
	}

	// -j TCPMSS --set-mss 1460
	mess := xt.Unknown([]byte{1460 & 0xff, (1460 >> 8) & 0xff})
	tcpMessTarget := &expr.Target{
		Name: "TCPMESS",
		Info: &mess,
	}

	// -m state --state ESTABLISHED
	ctMatch := &expr.Match{
		Name: "conntrack",
		Rev:  1,
		Info: &xt.ConntrackMtinfo1{
			ConntrackMtinfoBase: xt.ConntrackMtinfoBase{
				MatchFlags: 0x2001,
			},
			StateMask: 0x02,
		},
	}

	// compatPolicy.Proto should be tcp
	if compatPolicy, err := getCompatPolicy([]expr.Any{
		tcpMatch,
		tcpMessTarget,
		ctMatch,
	}); err != nil {
		t.Fatalf("getCompatPolicy fail %#v", err)
	} else if compatPolicy.Proto != unix.IPPROTO_TCP {
		t.Fatalf("getCompatPolicy wrong %#v", compatPolicy)
	}

	// should conflict
	if _, err := getCompatPolicy([]expr.Any{
		udpMatch,
		tcpMatch,
	},
	); err == nil {
		t.Fatalf("getCompatPolicy fail err should not be nil")
	}

	// compatPolicy should be nil
	if compatPolicy, err := getCompatPolicy([]expr.Any{
		ctMatch,
	}); err != nil {
		t.Fatalf("getCompatPolicy fail %#v", err)
	} else if compatPolicy != nil {
		t.Fatalf("getCompatPolicy fail compat policy of conntrack match should be nil")
	}
}
