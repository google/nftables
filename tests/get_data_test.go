package tests

import (
	"fmt"
	"github.com/google/nftables"
	"testing"
)

// Get table by net family and its name
func TestGetTable(t *testing.T) {
	conn := nftables.Conn{} // start up a conn

	table, _ := conn.GetTable("nat", nftables.TableFamilyIPv4)
	fmt.Println(table.Name)
}

// Get chain by chain's name
func TestGetChain(t *testing.T) {
	conn := nftables.Conn{} // start up a conn
	chain, _ := conn.GetChain("POSTROUTING") // get chain
	fmt.Println(chain.Name)
}

// Get set and set's elements by table and set's name
func TestGetSet(t *testing.T) {
	conn := nftables.Conn{} // start up a conn

	table, _ := conn.GetTable("nat", nftables.TableFamilyIPv4) // get table

	set, _ := conn.GetSetByName(table, "dest_addrs") // get set
	fmt.Println(set.Name)

	eles, _ := conn.GetSetElements(set)
	fmt.Println(eles)
}

// Get rules by table and chain
func TestGetRules(t *testing.T) {
	conn := nftables.Conn{} // start up a conn

	table, _ := conn.GetTable("nat", nftables.TableFamilyIPv4) // get table
	chain, _ := conn.GetChain("POSTROUTING")                   // get chain

	rules, _ := conn.GetRule(table, chain) // get rules
	for _, rule := range rules {
		fmt.Println(rule.Table.Name, rule.Table.Family, rule.Chain.Name, rule.Handle)
		// unpack exprs
		for _, expr := range rule.Exprs {
			fmt.Println(expr)
		}
	}
}