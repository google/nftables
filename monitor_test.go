package nftables_test

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/internal/nftest"
)

func TestMonitor(t *testing.T) {

	// Create a new network namespace to test these operations,
	// and tear down the namespace at test completion.
	c, newNS := nftest.OpenSystemConn(t, *enableSysTests)
	defer nftest.CleanupSystemConn(t, newNS)
	// Clear all rules at the beginning + end of the test.
	c.FlushRuleset()
	defer c.FlushRuleset()

	// default to monitor all
	monitor := nftables.NewMonitor()
	events, err := c.AddMonitor(monitor)
	if err != nil {
		t.Fatal(err)
	}

	var gotTable *nftables.Table
	var gotChain *nftables.Chain
	var gotRule *nftables.Rule
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case event, ok := <-events:
				if !ok {
					return
				}
				if event.Error != nil {
					err = fmt.Errorf("monitor err: %s", event.Error)
					return
				}
				switch event.Type {
				case nftables.EventTypeNewTable:
					gotTable = event.Data.(*nftables.Table)
				case nftables.EventTypeNewChain:
					gotChain = event.Data.(*nftables.Chain)
				case nftables.EventTypeNewRule:
					gotRule = event.Data.(*nftables.Rule)
				}
			}
		}
	}()

	nat := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "nat",
	})

	postrouting := c.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Table:    nat,
		Type:     nftables.ChainTypeNAT,
	})

	rule := c.AddRule(&nftables.Rule{
		Table: nat,
		Chain: postrouting,
		Exprs: []expr.Any{
			// payload load 4b @ network header + 12 => reg 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			// cmp eq reg 1 0x0245a8c0
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     net.ParseIP("192.168.69.2").To4(),
			},

			// masq
			&expr.Masq{},
		},
	})

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	// It takes time for the kernel to take effect
	time.Sleep(time.Second)
	monitor.Close()
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if gotTable.Family != nat.Family || gotTable.Name != nat.Name {
		t.Fatal("no want table", gotTable.Family, gotTable.Name)
	}
	if gotChain.Type != postrouting.Type || gotChain.Name != postrouting.Name ||
		*gotChain.Hooknum != *postrouting.Hooknum {
		t.Fatal("no want chain", gotChain.Type, gotChain.Name, gotChain.Hooknum)
	}
	if len(gotRule.Exprs) != len(rule.Exprs) {
		t.Fatal("no want rule")
	}
}
