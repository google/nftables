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
	"testing"

	"github.com/mdlayher/netlink"
)

func TestReadBufferSize(t *testing.T) {
	defaultEcho := (&Conn{}).getDefaultEchoReadBuffer()

	tests := []struct {
		name     string
		messages []netlinkMessage
		want     int
	}{
		{
			name:     "empty batch",
			messages: nil,
			want:     0,
		},
		{
			name: "batch without echo messages",
			messages: []netlinkMessage{
				{Header: netlink.Header{Flags: netlink.Request}},
				{Header: netlink.Header{Flags: netlink.Request | netlink.Create}},
			},
			want: 2 * 1024,
		},
		{
			name: "batch with echo message uses default echo read buffer",
			messages: []netlinkMessage{
				{Header: netlink.Header{Flags: netlink.Request | netlink.Create | netlink.Echo}},
			},
			want: defaultEcho,
		},
		{
			name: "batch with echo message and many messages",
			messages: func() []netlinkMessage {
				messages := make([]netlinkMessage, 10_000)
				for i := range messages {
					messages[i].Header.Flags = netlink.Request | netlink.Create | netlink.Echo
				}
				return messages
			}(),
			want: max(defaultEcho, 10_000*1024),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &Conn{messages: tt.messages}
			if got := cc.readBufferSize(); got != tt.want {
				t.Fatalf("readBufferSize() = %d, want %d", got, tt.want)
			}
		})
	}
}
