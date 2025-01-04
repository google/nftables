// Copyright 2025 Google LLC. All Rights Reserved.
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

package integration

import (
	"flag"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/internal/nftest"
	"github.com/vishvananda/netlink"
)

var enableSysTests = flag.Bool("run_system_tests", false, "Run tests that operate against the live kernel")

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func TestNFTables(t *testing.T) {
	tests := []struct {
		name          string
		scriptPath    string
		goCommands    func(t *testing.T, c *nftables.Conn)
		expectFailure bool
	}{
		{
			name:       "AddTable",
			scriptPath: "testdata/add_table.nft",
			goCommands: func(t *testing.T, c *nftables.Conn) {
				c.FlushRuleset()

				c.AddTable(&nftables.Table{
					Name:   "test-table",
					Family: nftables.TableFamilyINet,
				})

				err := c.Flush()
				if err != nil {
					t.Fatalf("Error creating table: %v", err)
				}
			},
		},
		{
			name:       "AddChain",
			scriptPath: "testdata/add_chain.nft",
			goCommands: func(t *testing.T, c *nftables.Conn) {
				c.FlushRuleset()

				table := c.AddTable(&nftables.Table{
					Name:   "test-table",
					Family: nftables.TableFamilyINet,
				})

				c.AddChain(&nftables.Chain{
					Name:     "test-chain",
					Table:    table,
					Hooknum:  nftables.ChainHookOutput,
					Priority: nftables.ChainPriorityNATDest,
					Type:     nftables.ChainTypeNAT,
				})

				err := c.Flush()
				if err != nil {
					t.Fatalf("Error creating table: %v", err)
				}
			},
		},
		{
			name:       "AddFlowtables",
			scriptPath: "testdata/add_flowtables.nft",
			goCommands: func(t *testing.T, c *nftables.Conn) {
				devices := []string{"dummy0"}
				c.FlushRuleset()
				// add + delete + add for flushing all the table
				table := c.AddTable(&nftables.Table{
					Family: nftables.TableFamilyINet,
					Name:   "test-table",
				})

				devicesSet := &nftables.Set{
					Table:        table,
					Name:         "test-set",
					KeyType:      nftables.TypeIFName,
					KeyByteOrder: binaryutil.NativeEndian,
				}

				elements := []nftables.SetElement{}
				for _, dev := range devices {
					elements = append(elements, nftables.SetElement{
						Key: ifname(dev),
					})
				}

				if err := c.AddSet(devicesSet, elements); err != nil {
					t.Errorf("failed to add Set %s : %v", devicesSet.Name, err)
				}

				flowtable := &nftables.Flowtable{
					Table:    table,
					Name:     "test-flowtable",
					Devices:  devices,
					Hooknum:  nftables.FlowtableHookIngress,
					Priority: nftables.FlowtablePriorityRef(5),
				}
				c.AddFlowtable(flowtable)

				chain := c.AddChain(&nftables.Chain{
					Name:     "test-chain",
					Table:    table,
					Type:     nftables.ChainTypeFilter,
					Hooknum:  nftables.ChainHookForward,
					Priority: nftables.ChainPriorityMangle,
				})

				c.AddRule(&nftables.Rule{
					Table: table,
					Chain: chain,
					Exprs: []expr.Any{
						&expr.Meta{Key: expr.MetaKeyIIFNAME, SourceRegister: false, Register: 0x1},
						&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetName: "test-set", Invert: true},
						&expr.Verdict{Kind: expr.VerdictReturn},
					},
				})

				c.AddRule(&nftables.Rule{
					Table: table,
					Chain: chain,
					Exprs: []expr.Any{
						&expr.Meta{Key: expr.MetaKeyOIFNAME, SourceRegister: false, Register: 0x1},
						&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetName: "test-set", Invert: true},
						&expr.Verdict{Kind: expr.VerdictReturn},
					},
				})

				c.AddRule(&nftables.Rule{
					Table: table,
					Chain: chain,
					Exprs: []expr.Any{
						&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeySTATE, Direction: 0x0},
						&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 0x4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED), Xor: binaryutil.NativeEndian.PutUint32(0)},
						&expr.Cmp{Op: 0x1, Register: 0x1, Data: []uint8{0x0, 0x0, 0x0, 0x0}},
						&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeyPKTS, Direction: 0x0},
						&expr.Cmp{Op: expr.CmpOpGt, Register: 0x1, Data: binaryutil.NativeEndian.PutUint64(20)},
						&expr.FlowOffload{Name: "test-flowtable"},
						&expr.Counter{},
					},
				})

				if err := c.Flush(); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new network namespace to test these operations,
			// and tear down the namespace at test completion.
			c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
			defer nftest.CleanupSystemConn(t, newNS)

			// Real interface must exist otherwise some nftables will fail
			la := netlink.NewLinkAttrs()
			la.Name = "dummy0"
			dummy := &netlink.Dummy{LinkAttrs: la}
			if err := netlink.LinkAdd(dummy); err != nil {
				t.Fatal(err)
			}

			scriptOutput, err := applyNFTRuleset(tt.scriptPath)
			if err != nil {
				t.Fatalf("Failed to apply nftables script: %v\noutput:%s", err, scriptOutput)
			}
			if len(scriptOutput) > 0 {
				t.Logf("nft output:\n%s", scriptOutput)
			}

			// Retrieve nftables state using nft
			expectedOutput, err := listNFTRuleset()
			if err != nil {
				t.Fatalf("Failed to list nftables ruleset: %v\noutput:%s", err, expectedOutput)
			}
			t.Logf("Expected output:\n%s", expectedOutput)

			// Program nftables using your Go code
			if err := flushNFTRuleset(); err != nil {
				t.Fatalf("Failed to flush nftables ruleset: %v", err)
			}
			tt.goCommands(t, c)

			// Retrieve nftables state using nft
			actualOutput, err := listNFTRuleset()
			if err != nil {
				t.Fatalf("Failed to list nftables ruleset: %v\noutput:%s", err, actualOutput)
			}

			t.Logf("Actual output:\n%s", actualOutput)

			if expectedOutput != actualOutput {
				t.Errorf("nftables ruleset mismatch:\n%s", cmp.Diff(expectedOutput, actualOutput))
			}

			if err := flushNFTRuleset(); err != nil {
				t.Fatalf("Failed to flush nftables ruleset: %v", err)
			}
		})
	}
}

func applyNFTRuleset(scriptPath string) (string, error) {
	cmd := exec.Command("nft", "--debug=all", "-f", scriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return strings.TrimSpace(string(out)), nil
}

func listNFTRuleset() (string, error) {
	cmd := exec.Command("nft", "list", "ruleset")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return strings.TrimSpace(string(out)), nil
}

func flushNFTRuleset() error {
	cmd := exec.Command("nft", "flush", "ruleset")
	return cmd.Run()
}
