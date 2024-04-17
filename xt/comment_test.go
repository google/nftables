package xt

import (
	"reflect"
	"strings"
	"testing"
)

func TestComment(t *testing.T) {
	t.Parallel()
	payload := Comment("The quick brown fox jumps over the lazy dog.")
	oversized := Comment(strings.Repeat("foobar", 100))
	tests := []struct {
		name   string
		info   InfoAny
		errmsg string
	}{
		{
			name: "un/marshal Comment round-trip",
			info: &payload,
		},
		{
			name:   "marshal oversized Comment",
			info:   &oversized,
			errmsg: "comment must be less than 256 bytes, got 600 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.info.marshal(0, 0)
			if err != nil {
				if tt.errmsg != "" && err.Error() == tt.errmsg {
					return
				}
				t.Fatalf("marshal error: %+v", err)

			}
			if len(data) != CommentSize {
				t.Fatalf("marshal error: invalid size %d", len(data))
			}
			if data[len(data)-1] != 0 {
				t.Fatalf("marshal error: invalid termination")
			}
			var comment Comment
			var recoveredInfo InfoAny = &comment
			err = recoveredInfo.unmarshal(0, 0, data)
			if err != nil {
				t.Fatalf("unmarshal error: %+v", err)
			}
			if !reflect.DeepEqual(tt.info, recoveredInfo) {
				t.Fatalf("original %+v and recovered %+v are different", tt.info, recoveredInfo)
			}
		})
	}

	oversizeddata := []byte(oversized)
	var comment Comment
	if err := (&comment).unmarshal(0, 0, oversizeddata); err == nil {
		t.Fatalf("unmarshal: expected error, but got nil")
	}
}
