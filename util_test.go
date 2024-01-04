package nftables

import (
	"net"
	"reflect"
	"testing"
)

func TestGetFirstIPFromCIDR(t *testing.T) {
	type args struct {
		cidr string
	}
	tests := []struct {
		name    string
		args    args
		want    *net.IP
		wantErr bool
	}{
		{
			name:    "Test 0",
			args:    args{cidr: "fakecidr"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Test 1",
			args:    args{cidr: "10.0.0.0/24"},
			want:    &net.IP{10, 0, 0, 0},
			wantErr: false,
		},
		{
			name:    "Test 2",
			args:    args{cidr: "10.0.0.20/24"},
			want:    &net.IP{10, 0, 0, 0},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetFirstIPFromCIDR(tt.args.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetFirstIPFromCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetFirstIPFromCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetLastIPFromCIDR(t *testing.T) {
	type args struct {
		cidr string
	}
	tests := []struct {
		name    string
		args    args
		want    *net.IP
		wantErr bool
	}{
		{
			name:    "Test 0",
			args:    args{cidr: "fakecidr"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Test 1",
			args:    args{cidr: "10.0.0.0/24"},
			want:    &net.IP{10, 0, 0, 255},
			wantErr: false,
		},
		{
			name:    "Test 2",
			args:    args{cidr: "10.0.0.20/24"},
			want:    &net.IP{10, 0, 0, 255},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetLastIPFromCIDR(tt.args.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLastIPFromCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetLastIPFromCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}
