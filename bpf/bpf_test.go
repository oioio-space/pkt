//go:build linux

package bpf_test

import (
	"testing"
	pkgbpf "github.com/oioio-space/pkt/bpf"
)

func TestCompile(t *testing.T) {
	cases := []struct {
		expr    string
		wantErr bool
	}{
		{"tcp", false},
		{"tcp port 80", false},
		{"ip and tcp", false},
		{"host 192.168.1.1", false},
		{"", true},
	}
	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			instr, err := pkgbpf.Compile(c.expr)
			if (err != nil) != c.wantErr {
				t.Fatalf("Compile(%q): err=%v wantErr=%v", c.expr, err, c.wantErr)
			}
			if !c.wantErr && len(instr) == 0 {
				t.Errorf("Compile(%q): 0 instructions", c.expr)
			}
		})
	}
}
