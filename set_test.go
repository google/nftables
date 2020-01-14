package nftables

import (
	"reflect"
	"testing"
)

func genSetKeyType(types ...uint32) uint32 {
	c := types[0]
	for i := 1; i < len(types); i++ {
		c = c<<SetConcatTypeBits | types[i]
	}
	return c
}

func TestValidateNFTMagic(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		nftMagicPacked uint32
		pass           bool
		invalid        []uint32
	}{
		{
			name:           "Single valid nftMagic",
			nftMagicPacked: genSetKeyType(7),
			pass:           true,
			invalid:        nil,
		},
		{
			name:           "Single invalid nftMagic",
			nftMagicPacked: genSetKeyType(25),
			pass:           false,
			invalid:        []uint32{25},
		},
		{
			name:           "Multiple valid nftMagic",
			nftMagicPacked: genSetKeyType(7, 13),
			pass:           true,
			invalid:        nil,
		},
		{
			name:           "Multiple nftMagic with 1 invalid",
			nftMagicPacked: genSetKeyType(7, 13, 25),
			pass:           false,
			invalid:        []uint32{25},
		},
		{
			name:           "Multiple nftMagic with 2 invalid",
			nftMagicPacked: genSetKeyType(7, 13, 25, 26),
			pass:           false,
			invalid:        []uint32{26, 25},
			// Invalid entries will appear in reverse order
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalid, pass := validateKeyType(tt.nftMagicPacked)
			if pass && !tt.pass {
				t.Fatalf("expected to fail but succeeded")
			}
			if !pass && tt.pass {
				t.Fatalf("expected to succeed but failed with invalid nftMagic: %+v", invalid)
			}
			if !reflect.DeepEqual(tt.invalid, invalid) {
				t.Fatalf("Expected invalid: %+v but got: %+v", tt.invalid, invalid)
			}
		})
	}
}

func TestConcatSetType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		types       []SetDatatype
		pass        bool
		concatName  string
		concatBytes uint32
		concatMagic uint32
	}{
		{
			name:  "Concatenate six (too many) IPv4s",
			types: []SetDatatype{TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr},
			pass:  false,
		},
		{
			name:        "Concatenate five IPv4s",
			types:       []SetDatatype{TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr},
			pass:        true,
			concatName:  "ipv4_addr . ipv4_addr . ipv4_addr . ipv4_addr . ipv4_addr",
			concatBytes: 20,
			concatMagic: 0x071c71c7,
		},
		{
			name:        "Concatenate IPv6 and port",
			types:       []SetDatatype{TypeIP6Addr, TypeInetService},
			pass:        true,
			concatName:  "ipv6_addr . inet_service",
			concatBytes: 20,
			concatMagic: 0x0000020d,
		},
		{
			name:        "Concatenate protocol and port",
			types:       []SetDatatype{TypeInetProto, TypeInetService},
			pass:        true,
			concatName:  "inet_proto . inet_service",
			concatBytes: 8,
			concatMagic: 0x0000030d,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.pass {
				defer func() {
					if recover() == nil {
						t.Fatalf("ConcatSetType() should have paniced but did not")
					}
				}()
			}
			concat := ConcatSetType(tt.types...)
			if tt.concatName != concat.Name {
				t.Errorf("invalid concatinated name: expceted %s but got %s", tt.concatName, concat.Name)
			}
			if tt.concatBytes != concat.Bytes {
				t.Errorf("invalid concatinated number of bytes: expceted %d but got %d", tt.concatBytes, concat.Bytes)
			}
			if tt.concatMagic != concat.nftMagic {
				t.Errorf("invalid concatinated magic: expceted %08x but got %08x", tt.concatMagic, concat.nftMagic)
			}
		})
	}
}
