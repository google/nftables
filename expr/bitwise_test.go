package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestBitwise(t *testing.T) {
	t.Parallel()
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
				// By specifying Xor to 0x0,0x0,0x0,0x0 and Mask to 0xff,0xff,0x0,0x0
				// an expression will match /16 IPv4 address.
				Xor:  []byte{0x0, 0x0, 0x0, 0x0},
				Mask: []byte{0xff, 0xff, 0x0, 0x0},
			},
		},
		{
			name: "Unmarshal Bitwise right shift case",
			bw: Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            2,
				Op:             BitwiseOpRshift,
				Data:           []byte{0x06, 0x00, 0x00, 0x00},
			},
		},
		{
			name: "Unmarshal Bitwise left shift case",
			bw: Bitwise{
				SourceRegister: 1,
				DestRegister:   2,
				Len:            4,
				Op:             BitwiseOpLshift,
				Data:           []byte{0x08, 0x00, 0x00, 0x00},
			},
		},
		{
			name: "Unmarshal Bitwise and with immediate case",
			bw: Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Op:             BitwiseOpAnd,
				Data:           []byte{0xff, 0x00, 0xff, 0x00},
			},
		},
		{
			name: "Unmarshal Bitwise xor with register case",
			bw: Bitwise{
				SourceRegister:  1,
				SourceRegister2: 2,
				DestRegister:    1,
				Len:             4,
				Op:              BitwiseOpXor,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nbw := Bitwise{}
			data, err := tt.bw.marshal(0 /* don't care in this test */)
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
					if err := nbw.unmarshal(0, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.bw, nbw) {
				t.Fatalf("original %+v and recovered %+v Bitwise structs are different", tt.bw, nbw)
			}
		})
	}
}

func TestBitwiseMarshalAttributesPerOp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		bw      Bitwise
		want    []uint16
		notWant []uint16
	}{
		{
			name: "mask/xor keeps the legacy attribute set",
			bw: Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0xff, 0xff, 0x0, 0x0},
				Xor:            []byte{0x0, 0x0, 0x0, 0x0},
			},
			want:    []uint16{unix.NFTA_BITWISE_MASK, unix.NFTA_BITWISE_XOR},
			notWant: []uint16{NFTA_BITWISE_OP, NFTA_BITWISE_DATA, NFTA_BITWISE_SREG2},
		},
		{
			name: "shift sends op and data only",
			bw: Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            2,
				Op:             BitwiseOpRshift,
				Data:           []byte{0x06, 0x00, 0x00, 0x00},
			},
			want:    []uint16{NFTA_BITWISE_OP, NFTA_BITWISE_DATA},
			notWant: []uint16{unix.NFTA_BITWISE_MASK, unix.NFTA_BITWISE_XOR, NFTA_BITWISE_SREG2},
		},
		{
			name: "boolean op with immediate sends data, not sreg2",
			bw: Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Op:             BitwiseOpOr,
				Data:           []byte{0x01, 0x00, 0x00, 0x00},
			},
			want:    []uint16{NFTA_BITWISE_OP, NFTA_BITWISE_DATA},
			notWant: []uint16{unix.NFTA_BITWISE_MASK, unix.NFTA_BITWISE_XOR, NFTA_BITWISE_SREG2},
		},
		{
			name: "boolean op with register sends sreg2, not data",
			bw: Bitwise{
				SourceRegister:  1,
				SourceRegister2: 2,
				DestRegister:    1,
				Len:             4,
				Op:              BitwiseOpAnd,
			},
			want:    []uint16{NFTA_BITWISE_OP, NFTA_BITWISE_SREG2},
			notWant: []uint16{unix.NFTA_BITWISE_MASK, unix.NFTA_BITWISE_XOR, NFTA_BITWISE_DATA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.bw.marshalData(0)
			if err != nil {
				t.Fatalf("marshalData error: %+v", err)
			}
			attrs, err := netlink.UnmarshalAttributes(data)
			if err != nil {
				t.Fatalf("UnmarshalAttributes error: %+v", err)
			}
			present := make(map[uint16]bool, len(attrs))
			for _, a := range attrs {
				present[a.Type&^unix.NLA_F_NESTED] = true
			}
			for _, typ := range tt.want {
				if !present[typ] {
					t.Errorf("attribute %d missing", typ)
				}
			}
			for _, typ := range tt.notWant {
				if present[typ] {
					t.Errorf("attribute %d present, the kernel rejects it for this op", typ)
				}
			}
		})
	}
}
