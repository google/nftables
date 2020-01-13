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

package expr_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
)

// nfdump returns a hexdump of 4 bytes per line (like nft --debug=all), allowing
// users to make sense of large byte literals more easily.
func nfdump(b []byte) string {
	var buf bytes.Buffer
	i := 0
	for ; i < len(b); i += 4 {
		// TODO: show printable characters as ASCII
		fmt.Fprintf(&buf, "%02x %02x %02x %02x\n",
			b[i],
			b[i+1],
			b[i+2],
			b[i+3])
	}
	for ; i < len(b); i++ {
		fmt.Fprintf(&buf, "%02x ", b[i])
	}
	return buf.String()
}

// linediff returns a side-by-side diff of two nfdump() return values, flagging
// lines which are not equal with an exclamation point prefix.
func linediff(a, b string) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "got -- want\n")
	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")
	for idx, lineA := range linesA {
		if idx >= len(linesB) {
			break
		}
		lineB := linesB[idx]
		prefix := "! "
		if lineA == lineB {
			prefix = "  "
		}
		fmt.Fprintf(&buf, "%s%s -- %s\n", prefix, lineA, lineB)
	}
	return buf.String()
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func CheckNLReq(t *testing.T, wantMsg [][]byte, replies [][]netlink.Message) nltest.Func {
	return func(req []netlink.Message) ([]netlink.Message, error) {
		for idx, msg := range req {
			b, err := msg.MarshalBinary()
			if err != nil {
				return req, err
			}
			if len(b) < 16 {
				continue
			}
			b = b[16:]
			if len(wantMsg) == 0 {
				t.Errorf("no want entry for message %d: %x", idx, b)
				continue
			}
			if got, want := b, wantMsg[0]; !bytes.Equal(got, want) {
				t.Errorf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
			}

			wantMsg = wantMsg[1:]
		}

		if len(replies) > 0 {
			rep := replies[0]
			replies = replies[1:]
			return rep, nil
		} else {
			return req, nil
		}
	}
}
