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

package userdata_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/userdata"
)

func TestUserDataComment(t *testing.T) {
	r := nftables.Rule{}

	wantComment := "this is my comment"
	want := []byte{
		byte(userdata.TypeComment), // Type
		byte(len(wantComment) + 1), // Length (including terminating null byte)
	}
	want = append(want, []byte(wantComment)...) // Payload
	want = append(want, 0)                      // Terminating null byte

	r.UserData = userdata.AppendString(r.UserData, userdata.TypeComment, wantComment)

	if !bytes.Equal(r.UserData, want) {
		t.Fatalf("UserData mismatch: %s != %s",
			hex.EncodeToString(r.UserData),
			hex.EncodeToString(want))
	}

	if comment, ok := userdata.GetString(r.UserData, userdata.TypeComment); !ok {
		t.Fatalf("failed to get comment")
	} else if comment != wantComment {
		t.Fatalf("comment does not match: %s != %s", comment, wantComment)
	}
}

func TestUint32(t *testing.T) {
	// Define a custom type for storing a rule ID
	const TypeRuleID = userdata.TypesCount

	r := nftables.Rule{}

	wantRuleID := uint32(1234)
	want := []byte{byte(TypeRuleID), 4, 210, 4, 0, 0}

	r.UserData = userdata.AppendUint32(r.UserData, TypeRuleID, wantRuleID)

	if !bytes.Equal(r.UserData, want) {
		t.Fatalf("UserData mismatch: %x != %x", r.UserData, want)
	}

	if ruleID, ok := userdata.GetUint32(r.UserData, TypeRuleID); !ok {
		t.Fatalf("failed to get id")
	} else if ruleID != wantRuleID {
		t.Fatalf("id mismatch")
	}
}
