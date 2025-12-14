// Copyright 2018 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"github.com/google/nftables/binaryutil"
	"golang.org/x/sys/unix"
)

var (
	MaxIPv4 = net.IP{255, 255, 255, 255}
	MaxIPv6 = net.IP{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

func extraHeader(family uint8, resID uint16) []byte {
	return append([]byte{
		family,
		unix.NFNETLINK_V0,
	}, binaryutil.BigEndian.PutUint16(resID)...)
}

// General form of address family dependent message, see
// https://git.netfilter.org/libnftnl/tree/include/linux/netfilter/nfnetlink.h#29
type NFGenMsg struct {
	NFGenFamily uint8
	Version     uint8
	ResourceID  uint16
}

func (genmsg *NFGenMsg) Decode(b []byte) {
	if len(b) < 4 {
		return
	}
	genmsg.NFGenFamily = b[0]
	genmsg.Version = b[1]
	genmsg.ResourceID = binary.BigEndian.Uint16(b[2:])
}

// NetFirstAndLastIP takes the beginning address of an entire network in CIDR
// notation (e.g. 192.168.1.0/24) and returns the first and last IP addresses
// within the network (e.g. first 192.168.1.0, last 192.168.1.255).
//
// Note that these are the first and last IP addresses, not the first and last
// *usable* IP addresses (which would be 192.168.1.1 and 192.168.1.254,
// respectively, for 192.168.1.0/24).
func NetFirstAndLastIP(networkCIDR string) (first, last net.IP, err error) {
	_, subnet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, nil, err
	}

	first = make(net.IP, len(subnet.IP))
	last = make(net.IP, len(subnet.IP))

	switch len(subnet.IP) {
	case net.IPv4len:
		mask := binary.BigEndian.Uint32(subnet.Mask)
		ip := binary.BigEndian.Uint32(subnet.IP)
		// To achieve the first IP address, we need to AND the IP with the mask.
		// The AND operation will set all bits in the host part to 0.
		binary.BigEndian.PutUint32(first, ip&mask)
		// To achieve the last IP address, we need to OR the IP network with the inverted mask.
		// The AND between the IP and the mask will set all bits in the host part to 0, keeping the network part.
		// The XOR between the mask and 0xffffffff will set all bits in the host part to 1, and the network part to 0.
		// The OR operation will keep the host part unchanged, and sets the host part to all 1.
		binary.BigEndian.PutUint32(last, (ip&mask)|(mask^0xffffffff))
	case net.IPv6len:
		mask1 := binary.BigEndian.Uint64(subnet.Mask[:8])
		mask2 := binary.BigEndian.Uint64(subnet.Mask[8:])
		ip1 := binary.BigEndian.Uint64(subnet.IP[:8])
		ip2 := binary.BigEndian.Uint64(subnet.IP[8:])
		binary.BigEndian.PutUint64(first[:8], ip1&mask1)
		binary.BigEndian.PutUint64(first[8:], ip2&mask2)
		binary.BigEndian.PutUint64(last[:8], (ip1&mask1)|(mask1^0xffffffffffffffff))
		binary.BigEndian.PutUint64(last[8:], (ip2&mask2)|(mask2^0xffffffffffffffff))
	}

	return first, last, nil
}

// nextIp returns the next IP address after the given one.
// If the next address overflows, the sentinel values 0.0.0.0 (IPv4)
// or :: (IPv6) are returned.
func nextIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}

	next := make(net.IP, len(ip))
	copy(next, ip)

	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			return next
		}
	}

	// All bytes overflowed to 0
	return next
}

// NetInterval returns the half-open ([start, end)) interval of a CIDR string.
// This is the range that nftables uses for interval matching with set elements.
// Unlike NetFirstAndLastIP, the end value is one past the last IP in the
// network. If the last IP is overflowed, the end value will be a zero IP.
//
// For example, for the CIDR "10.0.0.0/24", NetInterval returns
// first=10.0.0.0 and last=10.0.1.0. Note that last is one more than the
// broadcast address of the CIDR.
func NetInterval(cidr string) (net.IP, net.IP, error) {
	first, last, err := NetFirstAndLastIP(cidr)
	if err != nil {
		return first, last, err
	}

	return first, nextIP(last), nil
}

// endIp returns the last address in a given network.
func endIp(netIp net.IP, mask net.IPMask) net.IP {
	ip := make(net.IP, len(netIp))
	copy(ip, netIp)

	for i := 0; i < len(mask); i++ {
		ipIdx := len(ip) - i - 1
		ip[ipIdx] = netIp[ipIdx] | ^mask[len(mask)-i-1]
	}

	return ip
}

// NetFromRange returns a CIDR IP network given a start and end address.
// If an exact match is found, ok will be true. If not, no IPNet will be returned, and ok will be false.
func NetFromRange(first net.IP, last net.IP) (*net.IPNet, bool, error) {
	ip1 := net.IP(first)
	ip2 := net.IP(last)

	maxLen := 32
	isIpv6 := ip1.To4() == nil

	if isIpv6 && ip2.To4() != nil || !isIpv6 && ip2.To4() == nil {
		return nil, false, errors.New("Cannot mix IPv4 and IPv6 or process empty IP.")
	}

	if isIpv6 {
		maxLen = 128
	}

	var match *net.IPNet
	for l := maxLen; l >= -1; l-- {
		cidrmask := net.CIDRMask(l, maxLen)
		ipmask := ip2.Mask(cidrmask)
		ipnet := net.IPNet{
			IP:   ipmask,
			Mask: cidrmask,
		}

		if ipnet.Contains(ip1) {
			match = &ipnet
			break
		}

	}

	matchFirst := match.IP.Equal(ip1)

	// short-circuit if first address is not start of the network
	if !matchFirst {
		return nil, matchFirst, nil
	}

	matchSecond := endIp(match.IP, match.Mask).Equal(ip2)

	if !matchSecond {
		return nil, matchSecond, nil
	}

	return match, true, nil
}

// NetFromInterval returns a CIDR IP network given a start and end address as found in intervals.
// This is similar to NetFromRange, but subtracts one address from the end of the range.
// If the resulting network is an exact match, ok will be true.
func NetFromInterval(first net.IP, last net.IP) (out *net.IPNet, ok bool, err error) {
	var previous net.IP

	if len(last) == 0 {
		if first.To4() == nil {
			previous = MaxIPv6
		} else {
			previous = MaxIPv4
		}
	} else {
		ip2, ok := netip.AddrFromSlice(last)
		if !ok {
			return nil, false, errors.New("Failed to construct slice from network.")
		}

		previous = ip2.Prev().AsSlice()
	}

	return NetFromRange(first, previous)
}
