//go:build windows

package filter

import (
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
	}{
		{"true", false},
		{"false", false},
		{"ip", false},
		{"tcp", false},
		{"tcp.DstPort == 80", false},
		{"ip and tcp", false},
		{"ip or udp", false},
		{"!tcp", false},
		{"not tcp", false},
		{"(ip and tcp) or udp", false},
		{"tcp.DstPort == 443 and ip.SrcAddr == 192.168.1.1", false},
		{"tcp.DstPort >= 1024", false},
		{"ip.Protocol != 0x06", false},
		{"==", true},
		{"ip and", true},
		{"", true},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			result, err := Parse("test", []byte(c.input))
			if (err != nil) != c.wantErr {
				t.Fatalf("Parse(%q): err=%v wantErr=%v", c.input, err, c.wantErr)
			}
			if !c.wantErr {
				if result == nil {
					t.Fatalf("Parse(%q): got nil result", c.input)
				}
				node, ok := result.(Node)
				if !ok {
					t.Fatalf("Parse(%q): result is not a Node: %T", c.input, result)
				}
				if node.nodeKind() == "" {
					t.Errorf("Parse(%q): empty node kind", c.input)
				}
			}
		})
	}
}
