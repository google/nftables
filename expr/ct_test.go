package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestCt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ct   Ct
	}{
		{
			name: "Unmarshal Ct status case",
			ct: Ct{
				Register: 1,
				Key:      CtKeySTATUS,
			},
		},
		{
			name: "Unmarshal Ct proto-dst direction original case",
			ct: Ct{
				Register:  1,
				Key:       CtKeyPROTODST,
				Direction: 0, // direction: original
			},
		},
		{
			name: "Unmarshal Ct src direction reply case",
			ct: Ct{
				Register:  1,
				Key:       CtKeySRC,
				Direction: 1, // direction: reply
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nct := Ct{}
			data, err := tt.ct.marshal(0 /* don't care in this test */)
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
					if err := nct.unmarshal(0, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.ct, nct) {
				t.Fatalf("original %+v and recovered %+v Ct structs are different", tt.ct, nct)
			}
		})
	}
}
