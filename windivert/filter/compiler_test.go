//go:build windows

package filter

import (
	"testing"
)

func TestCompile(t *testing.T) {
	cases := []struct {
		filter  string
		wantErr bool
		minLen  int
	}{
		{"true", false, 1},
		{"false", false, 1},
		{"ip", false, 1},
		{"tcp.DstPort == 80", false, 1},
		{"ip and tcp", false, 2},
		{"ip or udp", false, 2},
		{"!tcp", false, 1},
		{"tcp.DstPort >= 1024", false, 1},
		{"ip.SrcAddr == 192.168.1.1", false, 1},
		{"ip.Protocol != 0x06", false, 1},
		{"unknown.Field == 1", true, 0},
	}
	for _, c := range cases {
		t.Run(c.filter, func(t *testing.T) {
			prog, err := Compile(c.filter)
			if (err != nil) != c.wantErr {
				t.Fatalf("Compile(%q): err=%v wantErr=%v", c.filter, err, c.wantErr)
			}
			if !c.wantErr && len(prog) < c.minLen {
				t.Errorf("got %d objects, want >= %d", len(prog), c.minLen)
			}
		})
	}
}
