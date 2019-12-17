package nftables

import (
	"reflect"
	"testing"
)

func genSetKeyType(types ...uint32) uint32 {
	c := types[0]
	for i := 1; i < len(types); i++ {
		c = c<<SetConcateTypeBits | types[i]
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
			// Invalid entries will apprear in reverse order
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
