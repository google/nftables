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

	"github.com/google/nftables/binaryutil"
	"golang.org/x/sys/unix"
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
	if len(b) < 16 {
		return
	}
	genmsg.NFGenFamily = b[0]
	genmsg.Version = b[1]
	genmsg.ResourceID = binary.BigEndian.Uint16(b[2:])
}
