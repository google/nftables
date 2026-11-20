package nftables

import (
	"encoding/binary"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func hookAttrs(t *testing.T, extra ...netlink.Attribute) []byte {
	t.Helper()
	num := make([]byte, 4)
	binary.BigEndian.PutUint32(num, uint32(*ChainHookIngress))
	prio := make([]byte, 4)
	binary.BigEndian.PutUint32(prio, uint32(*ChainPriorityFilter))
	attrs := append([]netlink.Attribute{
		{Type: unix.NFTA_HOOK_HOOKNUM, Data: num},
		{Type: unix.NFTA_HOOK_PRIORITY, Data: prio},
	}, extra...)
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A chain attached to one device: the kernel sends NFTA_HOOK_DEV, which
// was being read and discarded.
func TestHookFromMsgReadsASingleDevice(t *testing.T) {
	_, _, devices, err := hookFromMsg(hookAttrs(t,
		netlink.Attribute{Type: unix.NFTA_HOOK_DEV, Data: []byte("eth0\x00")}))
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0] != "eth0" {
		t.Fatalf("devices = %v, want [eth0]", devices)
	}
}

// "devices = { eth0, eth1 }" arrives as a nested list instead.
func TestHookFromMsgReadsADeviceList(t *testing.T) {
	list, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nftaDeviceName, Data: []byte("eth0\x00")},
		{Type: nftaDeviceName, Data: []byte("eth1\x00")},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, devices, err := hookFromMsg(hookAttrs(t,
		netlink.Attribute{Type: unix.NLA_F_NESTED | nftaHookDevs, Data: list}))
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 || devices[0] != "eth0" || devices[1] != "eth1" {
		t.Fatalf("devices = %v, want [eth0 eth1]", devices)
	}
}

// A chain with no device, which is every base chain in the ip families,
// is unaffected.
func TestHookFromMsgWithoutADevice(t *testing.T) {
	hooknum, prio, devices, err := hookFromMsg(hookAttrs(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Errorf("devices = %v, want none", devices)
	}
	if hooknum == nil || prio == nil {
		t.Error("the hook number and priority must still be read")
	}
}
