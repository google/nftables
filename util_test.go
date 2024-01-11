package nftables

import (
	"net"
	"reflect"
	"testing"
)

func TestGetFirstAndLastIPFromCIDR(t *testing.T) {
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
			gotFirstIP, gotLastIP, err := GetFirstAndLastIPFromCIDR(tt.args.cidr)
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
