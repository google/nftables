package nftables

import (
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type nftMsgType uint16

// See: https://github.com/torvalds/linux/blob/cbd2257dc96e3e46217540fcb095a757ffa20d96/include/uapi/linux/netfilter/nf_tables.h#L110
const (
	nftMsgNewTable nftMsgType = iota
	nftMsgGetTable
	nftMsgDelTable
	nftMsgNewChain
	nftMsgGetChain
	nftMsgDelChain
	nftMsgNewRule
	nftMsgGetRule
	nftMsgDelRule
	nftMsgNewSet
	nftMsgGetSet
	nftMsgDelSet
	nftMsgNewSetElem
	nftMsgGetSetElem
	nftMsgDelSetElem
	nftMsgNewGen
	nftMsgGetGen
	nftMsgTrace
	nftMsgNewObj
	nftMsgGetObj
	nftMsgDelObj
	nftMsgGetObjReset
	nftMsgNewFlowtable
	nftMsgGetFlowtable
	nftMsgDelFlowtable
	nftMsgGetRuleReset
	nftMsgDestroyTable
	nftMsgDestroyChain
	nftMsgDestroyRule
	nftMsgDestroySet
	nftMsgDestroySetElem
	nftMsgDestroyObj
	nftMsgDestroyFlowtable
	nftMsgGetSetElemReset
	nftMsgMax
)

func (t nftMsgType) String() string {
	switch t {
	case nftMsgNewTable:
		return "NFT_MSG_NEWTABLE"
	case nftMsgGetTable:
		return "NFT_MSG_GETTABLE"
	case nftMsgDelTable:
		return "NFT_MSG_DELTABLE"
	case nftMsgNewChain:
		return "NFT_MSG_NEWCHAIN"
	case nftMsgGetChain:
		return "NFT_MSG_GETCHAIN"
	case nftMsgDelChain:
		return "NFT_MSG_DELCHAIN"
	case nftMsgNewRule:
		return "NFT_MSG_NEWRULE"
	case nftMsgGetRule:
		return "NFT_MSG_GETRULE"
	case nftMsgDelRule:
		return "NFT_MSG_DELRULE"
	case nftMsgNewSet:
		return "NFT_MSG_NEWSET"
	case nftMsgGetSet:
		return "NFT_MSG_GETSET"
	case nftMsgDelSet:
		return "NFT_MSG_DELSET"
	case nftMsgNewSetElem:
		return "NFT_MSG_NEWSETELEM"
	case nftMsgGetSetElem:
		return "NFT_MSG_GETSETELEM"
	case nftMsgDelSetElem:
		return "NFT_MSG_DELSETELEM"
	case nftMsgNewGen:
		return "NFT_MSG_NEWGEN"
	case nftMsgGetGen:
		return "NFT_MSG_GETGEN"
	case nftMsgTrace:
		return "NFT_MSG_TRACE"
	case nftMsgNewObj:
		return "NFT_MSG_NEWOBJ"
	case nftMsgGetObj:
		return "NFT_MSG_GETOBJ"
	case nftMsgDelObj:
		return "NFT_MSG_DELOBJ"
	case nftMsgGetObjReset:
		return "NFT_MSG_GETOBJ_RESET"
	case nftMsgNewFlowtable:
		return "NFT_MSG_NEWFLOWTABLE"
	case nftMsgGetFlowtable:
		return "NFT_MSG_GETFLOWTABLE"
	case nftMsgDelFlowtable:
		return "NFT_MSG_DELFLOWTABLE"
	case nftMsgGetRuleReset:
		return "NFT_MSG_GETRULE_RESET"
	case nftMsgDestroyTable:
		return "NFT_MSG_DESTROYTABLE"
	case nftMsgDestroyChain:
		return "NFT_MSG_DESTROYCHAIN"
	case nftMsgDestroyRule:
		return "NFT_MSG_DESTROYRULE"
	case nftMsgDestroySet:
		return "NFT_MSG_DESTROYSET"
	case nftMsgDestroySetElem:
		return "NFT_MSG_DESTROYSETELEM"
	case nftMsgDestroyObj:
		return "NFT_MSG_DESTROYOBJ"
	case nftMsgDestroyFlowtable:
		return "NFT_MSG_DESTROYFLOWTABLE"
	case nftMsgGetSetElemReset:
		return "NFT_MSG_GETSETELEM_RESET"
	default:
		return fmt.Sprintf("Unknown NftMsgType(0x%X)", uint16(t))
	}
}

func (t nftMsgType) HeaderType() netlink.HeaderType {
	return netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | uint16(t))
}

func (t nftMsgType) Ptr() *nftMsgType {
	return &t
}

func parseNftMsgType(ht netlink.HeaderType) (*nftMsgType, error) {
	subsys := (uint16(ht) >> 8) & 0xff
	if subsys != unix.NFNL_SUBSYS_NFTABLES {
		return nil, fmt.Errorf("not an nftables subsystem: %d", subsys)
	}

	msgType := uint16(ht) & 0xff
	if msgType >= uint16(nftMsgMax) {
		return nil, fmt.Errorf("invalid nftables message type: %d", msgType)
	}

	return nftMsgType(msgType).Ptr(), nil
}
