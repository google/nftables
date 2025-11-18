package nftables

import (
	"net"
	"reflect"
	"testing"
)

func TestNetFirstAndLastIP(t *testing.T) {
	type args struct {
		cidr string
	}
	tests := []struct {
		name        string
		args        args
		wantFirstIP net.IP
		wantLastIP  net.IP
		wantErr     bool
	}{
		{
			name:        "Test Fake",
			args:        args{cidr: "fakecidr"},
			wantFirstIP: nil,
			wantLastIP:  nil,
			wantErr:     true,
		},
		{
			name:        "Test IPV4 1",
			args:        args{cidr: "10.0.0.0/24"},
			wantFirstIP: net.IP{10, 0, 0, 0},
			wantLastIP:  net.IP{10, 0, 0, 255},
			wantErr:     false,
		},
		{
			name:        "Test IPV4 2",
			args:        args{cidr: "10.0.0.20/24"},
			wantFirstIP: net.IP{10, 0, 0, 0},
			wantLastIP:  net.IP{10, 0, 0, 255},
			wantErr:     false,
		},
		{
			name:        "Test IPV4 2",
			args:        args{cidr: "10.0.0.0/19"},
			wantFirstIP: net.IP{10, 0, 0, 0},
			wantLastIP:  net.IP{10, 0, 31, 255},
			wantErr:     false,
		},
		{
			name:        "Test IPV6 1",
			args:        args{cidr: "ff00::/16"},
			wantFirstIP: net.ParseIP("ff00::"),
			wantLastIP:  net.ParseIP("ff00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
			wantErr:     false,
		},
		{
			name:        "Test IPV6 2",
			args:        args{cidr: "2001:db8::/62"},
			wantFirstIP: net.ParseIP("2001:db8::"),
			wantLastIP:  net.ParseIP("2001:db8:0000:0003:ffff:ffff:ffff:ffff"),
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFirstIP, gotLastIP, err := NetFirstAndLastIP(tt.args.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFirstAndLastIPFromCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFirstIP, tt.wantFirstIP) {
				t.Errorf("GetFirstAndLastIPFromCIDR() gotFirstIP = %v, want %v", gotFirstIP, tt.wantFirstIP)
			}
			if !reflect.DeepEqual(gotLastIP, tt.wantLastIP) {
				t.Errorf("GetFirstAndLastIPFromCIDR() gotLastIP = %v, want %v", gotLastIP, tt.wantLastIP)
			}
		})
	}
}

func TestNetInterval(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		wantFirstIP net.IP
		wantLastIP  net.IP
		wantErr     bool
	}{
		{
			name:        "Test Invalid",
			cidr:        "invalid-cidr",
			wantFirstIP: nil,
			wantLastIP:  nil,
			wantErr:     true,
		},
		{
			name:        "Test IPV4 /0",
			cidr:        "0.0.0.0/0",
			wantFirstIP: net.IP{0, 0, 0, 0},
			wantLastIP:  net.IP{0, 0, 0, 0},
			wantErr:     false,
		},
		{
			name:        "Test IPV4 /8",
			cidr:        "10.0.0.0/8",
			wantFirstIP: net.IP{10, 0, 0, 0},
			wantLastIP:  net.IP{11, 0, 0, 0},
			wantErr:     false,
		},
		{
			name:        "Test IPV4 /16",
			cidr:        "10.0.0.0/16",
			wantFirstIP: net.IP{10, 0, 0, 0},
			wantLastIP:  net.IP{10, 1, 0, 0},
			wantErr:     false,
		},
		{
			name:        "Test IPV4 /24",
			cidr:        "10.0.0.0/24",
			wantFirstIP: net.IP{10, 0, 0, 0},
			wantLastIP:  net.IP{10, 0, 1, 0},
			wantErr:     false,
		},
		{
			name:        "Test IPV4 /31 near max",
			cidr:        "255.255.255.255/31",
			wantFirstIP: net.IP{255, 255, 255, 254},
			wantLastIP:  net.IP{0, 0, 0, 0},
			wantErr:     false,
		},
		{
			name:        "Test IPV4 /32",
			cidr:        "10.0.0.1/32",
			wantFirstIP: net.IP{10, 0, 0, 1},
			wantLastIP:  net.IP{10, 0, 0, 2},
			wantErr:     false,
		},
		{
			name:        "Test IPv4 /0 with max",
			cidr:        "255.255.255.255/0",
			wantFirstIP: net.IP{0, 0, 0, 0},
			wantLastIP:  net.IP{0, 0, 0, 0},
			wantErr:     false,
		},
		{
			name:        "Test IPv6 /0",
			cidr:        "::/0",
			wantFirstIP: net.ParseIP("::"),
			wantLastIP:  net.ParseIP("::"),
			wantErr:     false,
		},
		{
			name:        "Test IPv6 /48",
			cidr:        "2001:db8::/48",
			wantFirstIP: net.ParseIP("2001:db8::"),
			wantLastIP:  net.ParseIP("2001:db8:1::"),
			wantErr:     false,
		},
		{
			name:        "Test IPv6 /64",
			cidr:        "2001:db8::/64",
			wantFirstIP: net.ParseIP("2001:db8::"),
			wantLastIP:  net.ParseIP("2001:db8::1:0:0:0:0"),
			wantErr:     false,
		},
		{
			name:        "Test IPv6 /120 near max",
			cidr:        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120",
			wantFirstIP: net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"),
			wantLastIP:  net.ParseIP("::"),
			wantErr:     false,
		},
		{
			name:        "Test IPv6 /128",
			cidr:        "2001:db8::1/128",
			wantFirstIP: net.ParseIP("2001:db8::1"),
			wantLastIP:  net.ParseIP("2001:db8::2"),
			wantErr:     false,
		},
		{
			name:        "Test IPv6 /0 with max",
			cidr:        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0",
			wantFirstIP: net.ParseIP("::"),
			wantLastIP:  net.ParseIP("::"),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFirstIP, gotLastIP, err := NetInterval(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetInterval() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFirstIP, tt.wantFirstIP) {
				t.Errorf("NetInterval() gotFirstIP = %v, want %v", gotFirstIP, tt.wantFirstIP)
			}
			if !reflect.DeepEqual(gotLastIP, tt.wantLastIP) {
				t.Errorf("NetInterval() gotLastIP = %v, want %v", gotLastIP, tt.wantLastIP)
			}
		})
	}
}
