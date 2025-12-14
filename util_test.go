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

func TestEndIp(t *testing.T) {
	tests := []struct {
		network   string
		wantEndIp string
	}{
		{
			network:   "10.0.0.0/24",
			wantEndIp: "10.0.0.255",
		},
		{
			network:   "192.168.4.32/27",
			wantEndIp: "192.168.4.63",
		},
		{
			network:   "2001:db8:100::/64",
			wantEndIp: "2001:db8:100:0:ffff:ffff:ffff:ffff",
		},
		{
			network:   "2001:db8:100:a:b::50/64",
			wantEndIp: "2001:db8:100:a:ffff:ffff:ffff:ffff",
		},
	}
	for _, tt := range tests {
		taddr, tnet, err := net.ParseCIDR(tt.network)
		if err != nil {
			t.Fatalf("endIp() error parsing test CIDR = %v", err)
		}

		t.Run(tnet.String(), func(t *testing.T) {
			gotEndIp := endIp(taddr, tnet.Mask)
			if !gotEndIp.Equal(net.ParseIP(tt.wantEndIp)) {
				t.Errorf("endIp() gotEndIp = %s, wantEndIp = %s", gotEndIp, tt.wantEndIp)
			}
		})
	}
}

func TestNetFromRange(t *testing.T) {
	tests := []struct {
		name    string
		first   string
		last    string
		wantNet string
		wantOk  bool
		wantErr bool
	}{
		{
			first:   "0.0.0.0",
			last:    "255.255.255.255",
			wantNet: "0.0.0.0/0",
			wantOk:  true,
			wantErr: false,
		},
		{
			first:   "0.0.0.1",
			last:    "255.255.255.254",
			wantNet: "", // not exactly 0.0.0.0/0
			wantOk:  false,
			wantErr: false,
		},
		{
			first:   "192.168.4.0",
			last:    "192.168.4.255",
			wantNet: "192.168.4.0/24",
			wantOk:  true,
			wantErr: false,
		},
		{
			first:   "192.0.2.16",
			last:    "192.0.2.30",
			wantNet: "", // not exactly 192.0.2.16/28
			wantOk:  false,
			wantErr: false,
		},
		{
			first:   "2001:db8:100::",
			last:    "2001:db8:100:ffff:ffff:ffff:ffff:ffff",
			wantNet: "2001:db8:100::/48",
			wantOk:  true,
			wantErr: false,
		},
		{
			first:   "2001:db8:100::100",
			last:    "2001:db8:100:0:ffff:ffff:ffff:ffff",
			wantNet: "", // not exactly 2001:db8:100::/64
			wantOk:  false,
			wantErr: false,
		},
		{
			first:   "2001:db8:100::",
			last:    "192.0.2.30",
			wantNet: "",
			wantOk:  true,
			wantErr: true,
		},
		{
			first:   "192.0.2.30",
			last:    "2001:db8:100::",
			wantNet: "",
			wantOk:  true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.first+"-"+tt.last, func(t *testing.T) {
			gotNet, gotOk, err := NetFromRange(net.ParseIP(tt.first), net.ParseIP(tt.last))
			if (err != nil) != tt.wantErr {
				t.Errorf("NetFromRange() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if tt.wantNet == "" {
				if gotNet != nil {
					t.Errorf("NetFromInterval() gotNet = %v, wantNet = nil", gotNet)
				}

				return
			}

			_, wantNetParsed, err := net.ParseCIDR(tt.wantNet)
			if err != nil {
				t.Fatalf("NetFromRange() error parsing test network = %v", err)
			}

			if tt.wantOk != gotOk {
				t.Errorf("NetFromRange() gotOk = %t, wantOk = %t", gotOk, tt.wantOk)
			}

			if !reflect.DeepEqual(gotNet, wantNetParsed) {
				t.Errorf("NetFromRange() gotNet = %+v, wantNet = %+v", gotNet, wantNetParsed)
			}
		})
	}
}

func TestNetFromInterval(t *testing.T) {
	tests := []struct {
		name    string
		first   string
		last    string
		wantNet string
		wantOk  bool
		wantErr bool
	}{
		{
			first:   "192.0.2.16",
			last:    "192.0.2.32",
			wantNet: "192.0.2.16/28",
			wantOk:  true,
			wantErr: false,
		},
		{
			first:   "128.0.0.0",
			last:    "",
			wantNet: "128.0.0.0/1",
			wantOk:  true,
			wantErr: false,
		},
		{
			first:   "2001:db8:100::",
			last:    "2001:db8:101::",
			wantNet: "2001:db8:100::/48",
			wantOk:  true,
			wantErr: false,
		},
		{
			first:   "2001:db8:a1:11::",
			last:    "2001:db8:a1:12::",
			wantNet: "2001:db8:a1:11::/64",
			wantOk:  true,
			wantErr: false,
		},
		{
			first:   "2001:db8:100::100",
			last:    "2001:db8:100:0:ffff:ffff:ffff:ffff",
			wantNet: "", // not exactly 2001:db8:100::/64
			wantOk:  false,
			wantErr: false,
		},
		{
			first:   "2001:db8:100::",
			last:    "192.0.2.30",
			wantNet: "",
			wantOk:  true,
			wantErr: true,
		},
		{
			first:   "192.0.2.30",
			last:    "2001:db8:100::",
			wantNet: "",
			wantOk:  true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.first+"-"+tt.last, func(t *testing.T) {
			gotNet, gotOk, err := NetFromInterval(net.ParseIP(tt.first), net.ParseIP(tt.last))
			if (err != nil) != tt.wantErr {
				t.Errorf("NetFromInterval() error = %v, wantErr = %v", err, tt.wantErr)
			}

			if tt.wantNet == "" {
				if gotNet != nil {
					t.Errorf("NetFromInterval() gotNet = %v, wantNet = nil", gotNet)
				}

				return
			}

			_, wantNetParsed, err := net.ParseCIDR(tt.wantNet)
			if err != nil {
				t.Fatalf("NetFromInterval() error parsing test network = %v", err)
			}

			if tt.wantOk != gotOk {
				t.Errorf("NetFromInterval() gotOk = %t, wantOk = %t", gotOk, tt.wantOk)
			}

			if !reflect.DeepEqual(gotNet, wantNetParsed) {
				t.Errorf("NetFromInterval() gotNet = %+v, wantNet = %+v", gotNet, wantNetParsed)
			}
		})
	}
}
