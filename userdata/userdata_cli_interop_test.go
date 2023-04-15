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
	"encoding/json"
	"flag"
	"os/exec"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/internal/nftest"
	"github.com/google/nftables/userdata"
)

var enableSysTests = flag.Bool("run_system_tests", false, "Run tests that operate against the live kernel")

type nftCliMetainfo struct {
	Version           string `json:"version,omitempty"`
	ReleaseName       string `json:"release_name,omitempty"`
	JSONSchemaVersion int    `json:"json_schema_version,omitempty"`
}

type nftCliTable struct {
	Family string `json:"family,omitempty"`
	Name   string `json:"name,omitempty"`
	Handle int    `json:"handle,omitempty"`
}

type nftCliChain struct {
	Family string `json:"family,omitempty"`
	Table  string `json:"table,omitempty"`
	Name   string `json:"name,omitempty"`
	Handle int    `json:"handle,omitempty"`
}

type nftCliExpr struct{}

type nftCliRule struct {
	Family  string       `json:"family,omitempty"`
	Table   string       `json:"table,omitempty"`
	Chain   string       `json:"chain,omitempty"`
	Handle  int          `json:"handle,omitempty"`
	Comment string       `json:"comment,omitempty"`
	Expr    []nftCliExpr `json:"expr"`
}

type nftCommand struct {
	Ruleset interface{}  `json:"ruleset"`
	Table   *nftCliTable `json:"table,omitempty"`
	Chain   *nftCliChain `json:"chain,omitempty"`
	Rule    *nftCliRule  `json:"rule,omitempty"`
}

type nftCliObject struct {
	Metainfo *nftCliMetainfo `json:"metainfo,omitempty"`
	Table    *nftCliTable    `json:"table,omitempty"`
	Chain    *nftCliChain    `json:"chain,omitempty"`
	Rule     *nftCliRule     `json:"rule,omitempty"`
	Add      *nftCommand     `json:"add,omitempty"`
	Flush    *nftCommand     `json:"flush,omitempty"`
}

type nftCli struct {
	Nftables []nftCliObject `json:"nftables"`
}

func TestCommentInteropGo2Cli(t *testing.T) {
	wantComment := "my comment"

	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	c.FlushRuleset()

	table := c.AddTable(&nftables.Table{
		Name:   "userdata-table",
		Family: nftables.TableFamilyIPv4,
	})

	chain := c.AddChain(&nftables.Chain{
		Name:  "userdata-chain",
		Table: table,
	})

	c.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: userdata.AppendString(nil, userdata.TypeComment, wantComment),
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	out := bytes.NewBuffer(nil)
	d := exec.Command("nft", "-j", "list", "table", "userdata-table")
	d.Stdout = out
	if err := d.Run(); err != nil {
		t.Fatal(err)
	}

	var outJson nftCli
	if err := json.Unmarshal(out.Bytes(), &outJson); err != nil {
		t.Fatal()
	}

	found := 0
	for _, e := range outJson.Nftables {
		if e.Rule == nil || e.Rule.Handle == 0 {
			continue
		}

		if e.Rule.Comment != wantComment {
			t.Fatal()
		}

		found++
	}

	if found != 1 {
		t.Fatalf("found %d rules", found)
	}

	c.DelTable(table)

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestCommentInteropCli2Go(t *testing.T) {
	wantComment := "my comment"

	inJson := nftCli{
		Nftables: []nftCliObject{
			{
				Metainfo: &nftCliMetainfo{
					JSONSchemaVersion: 1,
				},
			},
			{
				Flush: &nftCommand{
					Ruleset: nil,
				},
			},
			{
				Add: &nftCommand{
					Table: &nftCliTable{
						Family: "ip",
						Name:   "userdata-table",
					},
				},
			},
			{
				Add: &nftCommand{
					Chain: &nftCliChain{
						Family: "ip",
						Name:   "userdata-chain",
						Table:  "userdata-table",
					},
				},
			},
			{
				Add: &nftCommand{
					Rule: &nftCliRule{
						Family:  "ip",
						Table:   "userdata-table",
						Chain:   "userdata-chain",
						Comment: wantComment,
						Expr:    []nftCliExpr{},
					},
				},
			},
		},
	}

	in := bytes.NewBuffer(nil)
	if err := json.NewEncoder(in).Encode(inJson); err != nil {
		t.Fatal()
	}

	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)

	d := exec.Command("nft", "-j", "-f", "-")
	d.Stdin = in
	if err := d.Run(); err != nil {
		t.Fatal(err)
	}

	table := &nftables.Table{
		Name:   "userdata-table",
		Family: nftables.TableFamilyIPv4,
	}

	chain := &nftables.Chain{
		Name:  "userdata-chain",
		Table: table,
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != 1 {
		t.Fatal()
	}

	if comment, ok := userdata.GetString(rules[0].UserData, userdata.TypeComment); !ok {
		t.Fatalf("failed to find comment")
	} else if comment != wantComment {
		t.Fatalf("comment mismatch %q != %q", comment, wantComment)
	}
}
