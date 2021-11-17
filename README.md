[![Build Status](https://github.com/google/nftables/actions/workflows/push.yml/badge.svg)](https://github.com/google/nftables/actions/workflows/push.yml)
[![GoDoc](https://godoc.org/github.com/google/nftables?status.svg)](https://godoc.org/github.com/google/nftables)

## 1. Introduction
**This is not the correct repository for issues with the Linux nftables
project!** This repository contains a third-party Go package to programmatically
interact with nftables. Find the official nftables website at
https://wiki.nftables.org/

This package manipulates Linux nftables (the iptables successor). It is
implemented in pure Go, i.e. does not wrap libnftnl.

This is not an official Google product.

## 2. Breaking changes

This package is in very early stages, and only contains enough data types and
functions to install very basic nftables rules. It is likely that mistakes with
the data types/API will be identified as more functionality is added.

## 3. Contributions

Contributions are very welcome!


## 4. Examples

### 1. Get common data types of Nftables

#### 1.1. Get table by net family and its name

```go
conn := nftables.Conn{} // start up a conn

table, _ := conn.GetTable("nat", nftables.TableFamilyIPv4)
fmt.Println(table.Name)
```
#### 1.2. Get chain by chain's name

```go
conn := nftables.Conn{} // start up a conn
chain, _ := conn.GetChain("POSTROUTING") // get chain
fmt.Println(chain.Name)
```

#### 1.3. Get set and set's elements by table and set's name

```go
conn := nftables.Conn{} // start up a conn

table, _ := conn.GetTable("nat", nftables.TableFamilyIPv4) // get table


set, _ := conn.GetSetByName(table, "dest_addrs") // get set
fmt.Println(set.Name)

eles, _ := conn.GetSetElements(set)
fmt.Println(eles)
```

#### 1.4. Get rules by table and chain

```go
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
```

### 2. Insert common data types of Nftables

**wait for update**