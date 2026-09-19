package expr

import (
	"testing"

	"github.com/mdlayher/netlink"
)

// TestCtTimeoutUnmarshalMalformedNestedAttr verifies that a truncated nested
// NFTA_CT_TIMEOUT_DATA attribute returns an error instead of panicking.
// Regression for https://github.com/google/nftables/issues/367
func TestCtTimeoutUnmarshalMalformedNestedAttr(t *testing.T) {
	t.Parallel()

	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		// One-byte payload is shorter than an NLA header, so
		// NewAttributeDecoder returns (nil, err).
		{Type: NFTA_CT_TIMEOUT_DATA, Data: []byte{0xff}},
	})
	if err != nil {
		t.Fatal(err)
	}

	ct := &CtTimeout{}
	if err := ct.unmarshal(0, data); err == nil {
		t.Fatal("expected error unmarshaling malformed nested attribute, got nil")
	}
}
