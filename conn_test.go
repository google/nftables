// Copyright 2026 Google LLC. All Rights Reserved.
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

import "testing"

func TestMnlSocketBufferSize(t *testing.T) {
	for _, tt := range []struct {
		name     string
		pageSize int
		want     int
	}{
		{name: "4KiB", pageSize: 4096, want: 4096},
		{name: "8KiB", pageSize: 8192, want: 8192},
		{name: "16KiB", pageSize: 16384, want: 8192},
		{name: "64KiB", pageSize: 65536, want: 8192},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := mnlSocketBufferSize(tt.pageSize); got != tt.want {
				t.Errorf("mnlSocketBufferSize(%d) = %d, want %d", tt.pageSize, got, tt.want)
			}
		})
	}
}

func TestRecvBufSize(t *testing.T) {
	for _, tt := range []struct {
		name     string
		pageSize int
		want     int
	}{
		// The ACK buffer is larger for small pages.
		{name: "4KiB", pageSize: 4096, want: 69652},
		{name: "8KiB", pageSize: 8192, want: 73748},
		// The dump buffer is larger for large pages.
		{name: "16KiB", pageSize: 16384, want: 81919},
		{name: "64KiB", pageSize: 65536, want: 131071},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := recvBufSize(tt.pageSize); got != tt.want {
				t.Errorf("recvBufSize(%d) = %d, want %d", tt.pageSize, got, tt.want)
			}
		})
	}
}
