package nftables_test

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/internal/nftest"
)

func ExampleNewMonitor() {
	conn, err := nftables.New()
	if err != nil {
		log.Fatal(err)
	}

	mon := nftables.NewMonitor()
	defer mon.Close()
	events, err := conn.AddGenerationalMonitor(mon)
	if err != nil {
		log.Fatal(err)
	}
	for ev := range events {
		log.Printf("ev: %+v, data = %T", ev, ev.Changes)

		for _, change := range ev.Changes {
			switch change.Type {
			case nftables.MonitorEventTypeNewTable:
				log.Printf("data = %+v", change.Data.(*nftables.Table))
				// …more cases if needed…
			}
		}
	}
}

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
	events, err := c.AddGenerationalMonitor(monitor)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()

	var gotTable *nftables.Table
	var gotChain *nftables.Chain
	var gotRule *nftables.Rule
	wg := sync.WaitGroup{}
	wg.Add(1)
	var errMonitor error
	go func() {
		defer wg.Done()
		count := int32(0)
		for {
			event, ok := <-events
			if !ok {
				return
			}

			genMsg := event.GeneratedBy.Data.(*nftables.GenMsg)
			fileName := filepath.Base(os.Args[0])

			if genMsg.ProcComm != fileName {
				errMonitor = fmt.Errorf("procComm: %s, want: %s", genMsg.ProcComm, fileName)
				return
			}

			for _, change := range event.Changes {
				if change.Error != nil {
					errMonitor = fmt.Errorf("monitor err: %s", change.Error)
					return
				}

				switch change.Type {
				case nftables.MonitorEventTypeNewTable:
					gotTable = change.Data.(*nftables.Table)
					atomic.AddInt32(&count, 1)
				case nftables.MonitorEventTypeNewChain:
					gotChain = change.Data.(*nftables.Chain)
					atomic.AddInt32(&count, 1)
				case nftables.MonitorEventTypeNewRule:
					gotRule = change.Data.(*nftables.Rule)
					atomic.AddInt32(&count, 1)
				}
				if atomic.LoadInt32(&count) == 3 {
					return
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

	wg.Wait()

	if errMonitor != nil {
		t.Fatal("monitor err", errMonitor)
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
