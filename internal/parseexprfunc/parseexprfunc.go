package parseexprfunc

import (
	"github.com/mdlayher/netlink"
)

var (
	ParseExprBytesFunc func(fam byte, ad *netlink.AttributeDecoder, args ...string) ([]interface{}, error)
	ParseExprMsgFunc   func(fam byte, b []byte, args ...string) ([]interface{}, error)
)
