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

package expr

import (
	"encoding/binary"
	"testing"

	"github.com/mdlayher/netlink"
)

func TestTProxyUnmarshalFamily(t *testing.T) {
	t.Parallel()

	for _, family := range []byte{2, 10} {
		t.Run(map[byte]string{2: "IPv4", 10: "IPv6"}[family], func(t *testing.T) {
			data, err := netlink.MarshalAttributes([]netlink.Attribute{{
				Type: NFTA_TPROXY_FAMILY,
				Data: binary.BigEndian.AppendUint32(nil, uint32(family)),
			}})
			if err != nil {
				t.Fatalf("MarshalAttributes() error: %v", err)
			}

			var got TProxy
			if err := got.unmarshal(0, data); err != nil {
				t.Fatalf("unmarshal() error: %v", err)
			}
			if got.Family != family {
				t.Fatalf("unmarshal() family = %d, want %d", got.Family, family)
			}
		})
	}
}
