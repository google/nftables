[![Build Status](https://travis-ci.org/google/nftables.svg?branch=master)](https://travis-ci.org/google/nftables)
[![GoDoc](https://godoc.org/github.com/google/nftables?status.svg)](https://godoc.org/github.com/google/nftables)

This package manipulates Linux nftables (the iptables successor). It is
implemented in pure Go, i.e. does not wrap libnftnl.

This is not an official Google product.

## Alpha status

This package is in early stages, and only implements a subset of nftables
features. While the developers intend to keep interfaces & function signatures
backwards-compatible, no guarantees are made; bugs or any unexpected
structuring of nftables features may result in breaking changes.

## Usage

Issue commands to mutate or read nftables state. Commands that mutate state
(eg: `AddTable`, `AddChain`, `AddSet`, `AddRule`) are queued until `Flush`
is called.

### Expressions

The following expressions are implemented for use in rule logic:

TODO

### Examples

#### Drop outgoing packets to 1.2.3.4

```go
c := &nftables.Conn{}

myTable := c.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   "myFilter",
})

myChain := c.AddChain(&nftables.Chain{
	Name:     "myChain",
	Table:    myTable,
	Type:     nftables.ChainTypeFilter,
	Hooknum:  nftables.ChainHookOutput,
	Priority: nftables.ChainPriorityFilter,
})

c.AddRule(&nftables.Rule{
  Table: myTable,
  Chain: myChain,
  Exprs: []expr.Any{
    // payload load 4b @ network header + 16 => reg 1
    // (Load the destination IP into register 1)
    &expr.Payload{
      DestRegister: 1,
      Base:         expr.PayloadBaseNetworkHeader,
      Offset:       16,
      Len:          4,
    },
    // cmp eq reg 1 0x01020304
    // (bail if register 1 != 1.2.3.4)
    &expr.Cmp{
      Op:       expr.CmpOpEq,
      Register: 1,
      Data:     net.ParseIP("1.2.3.4").To4(),
    },
    // [ immediate reg 0 drop ]
    // (drop the packet)
    &expr.Verdict{
      Kind: expr.VerdictDrop,
    },
  },
})

if err := c.Flush(); err != nil {
  // handle error
}

```


## Contributions

Contributions are very welcome!


