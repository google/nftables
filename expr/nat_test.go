package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestNat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		nat  NAT
	}{
		{
			name: "Unmarshal DNAT specified case",
			nat: NAT{
				Type:        NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
				Specified:   true,
			},
		},
		{
			name: "Unmarshal SNAT persistent case",
			nat: NAT{
				Type:        NATTypeSourceNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
				Persistent:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nnat := NAT{}
			data, err := tt.nat.marshal(0 /* don't care in this test */)
			if err != nil {
				t.Fatalf("marshal error: %+v", err)

			}
			ad, err := netlink.NewAttributeDecoder(data)
			if err != nil {
				t.Fatalf("NewAttributeDecoder() error: %+v", err)
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				if ad.Type() == unix.NFTA_EXPR_DATA {
					if err := nnat.unmarshal(0, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.nat, nnat) {
				t.Fatalf("original %+v and recovered %+v Ct structs are different", tt.nat, nnat)
			}
		})
	}
}
