package expr

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestTProxy(t *testing.T) {
	t.Parallel()
	fams := []byte{
		unix.NFPROTO_UNSPEC,
		unix.NFPROTO_INET,
		unix.NFPROTO_IPV4,
		unix.NFPROTO_ARP,
		unix.NFPROTO_NETDEV,
		unix.NFPROTO_BRIDGE,
		unix.NFPROTO_IPV6,
		unix.NFPROTO_DECNET,
		unix.NFPROTO_NUMPROTO,
	}

	for idx, fam := range fams {
		tests := map[string]*TProxy{
			"empty-1": &TProxy{},
			"basic-1": &TProxy{Family: fam, RegPort: 1},
			"basic-2": &TProxy{Family: fam, RegPort: 1, RegAddr: 2},
		}
		for name, origExpr := range tests {
			t.Run(fmt.Sprintf("%s_%d", name, idx), func(t *testing.T) {
				bin, err := origExpr.marshal(fam)
				if err != nil {
					t.Fatalf("on marshal(%d): %v", fam, err)
				}

				ad, err := netlink.NewAttributeDecoder(bin)
				if err != nil {
					t.Fatal(err)
				}
				ad.ByteOrder = binary.BigEndian

				parsed := exprFromName("tproxy").(*TProxy)
				for ad.Next() {
					switch ad.Type() {
					case unix.NFTA_EXPR_DATA:
						err = parsed.unmarshal(fam, ad.Bytes())
						if err != nil {
							t.Fatalf("on unmarshal(%d): %v", fam, err)
						}
					case unix.NFTA_EXPR_NAME:
						if ad.String() != "tproxy" {
							t.Fatalf("unexpected expr name: %q", ad.String())
						}
					default:
						t.Fatalf("unexpected expr attr: %d", ad.Type())
					}
				}

				if !reflect.DeepEqual(origExpr, parsed) {
					t.Fatalf("parse symmetry broken: expected %+v, got %+v", *origExpr, *parsed)
				}
			})
		}
	}
}
