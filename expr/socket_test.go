package expr

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestSocket(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		socket Socket
	}{
		{
			name: "Unmarshal `socket transparent`",
			socket: Socket{
				Key:      SocketKeyTransparent,
				Level:    0,
				Register: 1,
			},
		},
		{
			name: "Unmarshal `socket cgroup level 5`",
			socket: Socket{
				Key:      SocketKeyCgroupv2,
				Level:    5,
				Register: 1,
			},
		},
		{
			name: "Unmarshal `socket cgroup level 1`",
			socket: Socket{
				Key:      SocketKeyCgroupv2,
				Level:    1,
				Register: 1,
			},
		},
		{
			name: "Unmarshal `socket wildcard`",
			socket: Socket{
				Key:      SocketKeyWildcard,
				Level:    0,
				Register: 1,
			},
		},
		{
			name: "Unmarshal `socket mark`",
			socket: Socket{
				Key:      SocketKeyMark,
				Level:    0,
				Register: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nSocket := Socket{}
			data, err := tt.socket.marshal(0 /* don't care in this test */)
			if err != nil {
				t.Fatalf("marshal error: %+v", err)

			}
			ad, err := netlink.NewAttributeDecoder(data)
			if err != nil {
				t.Fatalf("NewAttributeDecoder() error: %+v", err)
			}
			ad.ByteOrder = binary.BigEndian
			for ad.Next() {
				if ad.Type() == unix.NFTA_EXPR_DATA {
					if err := nSocket.unmarshal(0, ad.Bytes()); err != nil {
						t.Errorf("unmarshal error: %+v", err)
						break
					}
				}
			}
			if !reflect.DeepEqual(tt.socket, nSocket) {
				t.Fatalf("original %+v and recovered %+v Socket structs are different", tt.socket, nSocket)
			}
		})
	}
}
