package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestBitwise(t *testing.T) {
	tests := []struct {
		name string
		bw   Bitwise
	}{
		{
			name: "Unmarshal Bitwise IPv4 case",
			bw: Bitwise{
				SourceRegister: 1,
				DestRegister:   2,
				Len:            4,
				Xor:            []byte{0x0, 0x0, 0x0, 0x0},
				Mask:           []byte{0xff, 0xff, 0x0, 0x0},
			},
		},
	}

	for _, tt := range tests {
		nbw := Bitwise{}
		data, err := tt.bw.marshal()
		if err != nil {
			t.Errorf("Test \"%s\" failed to marshal Bitwise struct with error: %+v", tt.name, err)
			continue
		}
		ad, err := netlink.NewAttributeDecoder(data)
		if err != nil {
			t.Errorf("Test \"%s\" failed to marshal Bitwise struct with error: %+v", tt.name, err)
			continue
		}
		ad.ByteOrder = binary.BigEndian
		for ad.Next() {
			if ad.Type() == unix.NFTA_EXPR_DATA {
				if err := nbw.unmarshal(ad.Bytes()); err != nil {
					t.Errorf("Test \"%s\" failed to unmarshal data into Bitwise struct with error: %+v", tt.name, err)
					break
				}
			}
		}
		if !reflect.DeepEqual(tt.bw, nbw) {
			t.Errorf("Test \"%s\" failed as original %+v and recovered %+v Bitwise structs are different", tt.name, tt.bw, nbw)
			continue
		}
	}
}
