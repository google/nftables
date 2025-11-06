package nftables

import (
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestParseNftMsgType(t *testing.T) {
	var tests = []struct {
		name           string
		headerType     netlink.HeaderType
		wantErr        bool
		wantNftMsgType *nftMsgType
		wantString     string
	}{
		{
			name:           "InvalidSubsystem",
			headerType:     netlink.HeaderType(unix.NFNL_SUBSYS_CTNETLINK << 8),
			wantErr:        true,
			wantNftMsgType: nil,
			wantString:     "",
		},
		{
			name:           "InvalidMsgType",
			headerType:     netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | uint16(nftMsgMax+1)),
			wantErr:        true,
			wantNftMsgType: nil,
			wantString:     "",
		},
		{
			name:           "NewTable",
			headerType:     netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | uint16(nftMsgNewTable)),
			wantErr:        false,
			wantNftMsgType: nftMsgNewTable.Ptr(),
			wantString:     "NFT_MSG_NEWTABLE",
		},
		{
			name:           "GetChain",
			headerType:     netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | uint16(nftMsgGetChain)),
			wantErr:        false,
			wantNftMsgType: nftMsgGetChain.Ptr(),
			wantString:     "NFT_MSG_GETCHAIN",
		},
		{
			name:           "DelSet",
			headerType:     netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | uint16(nftMsgDelSet)),
			wantErr:        false,
			wantNftMsgType: nftMsgDelSet.Ptr(),
			wantString:     "NFT_MSG_DELSET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNftMsgType(tt.headerType)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseHeaderType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && *got != *tt.wantNftMsgType {
				t.Errorf("parseHeaderType() = %v, want %v", got, tt.wantNftMsgType)
			}

			if !tt.wantErr && got.String() != tt.wantString {
				t.Errorf("nftMsgType.String() = %v, want %v", got.String(), tt.wantString)
			}
		})
	}
}

func TestNftMsgHeaderType(t *testing.T) {
	var tests = []struct {
		name    string
		msgType nftMsgType
		want    netlink.HeaderType
	}{
		{
			name:    "nftMsgNewTable",
			msgType: nftMsgNewTable,
			want:    netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | uint16(nftMsgNewTable)),
		},
		{
			name:    "nftMsgGetChain",
			msgType: nftMsgGetChain,
			want:    netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | uint16(nftMsgGetChain)),
		},
		{
			name:    "nftMsgDelSet",
			msgType: nftMsgDelSet,
			want:    netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | uint16(nftMsgDelSet)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msgType.HeaderType()
			if got != tt.want {
				t.Errorf("HeaderType() = %v, want %v", got, tt.want)
			}
		})
	}
}
