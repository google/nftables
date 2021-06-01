package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestOther(t *testing.T) {
	orig := &Other{
		Type: "testing",
		Attributes: []OtherAttribute{
			{1, []byte{66, 5}},
			{5, []byte("test")},
		},
	}

	data, err := Marshal(orig)
	if err != nil {
		t.Fatal("Error marshalling other: ", err)
	}

	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		t.Fatalf("NewAttributeDecoder() error: %+v", err)
	}
	ad.ByteOrder = binary.BigEndian
	if !ad.Next() {
		t.Fatal("too short")
	}
	if ad.Type() != unix.NFTA_EXPR_NAME || ad.String() != orig.Type {
		t.Fatalf("wrong name %d:%q", ad.Type(), ad.String())
	}

	if !ad.Next() {
		t.Fatal("too short")
	}
	decoded := &Other{Type: "testing"}
	if ad.Type() != unix.NFTA_EXPR_DATA {
		t.Fatal("Wrong type for data:", ad.Type())
	}
	if err := Unmarshal(ad.Bytes(), decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(orig, decoded) {
		t.Errorf("Wrong structure decoded: %+v vs %+v", decoded, orig)
	}
	if ad.Next() {
		t.Error("Got extra attribute: ", ad.Type())
	}
}
