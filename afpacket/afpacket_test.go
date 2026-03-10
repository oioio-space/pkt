//go:build linux

package afpacket_test

import (
	"testing"

	"pkt/afpacket"
)

func TestOptions(t *testing.T) {
	o := afpacket.DefaultOptions()
	afpacket.WithPromiscuous(false)(&o)
	afpacket.WithSnapLen(1500)(&o)
	afpacket.WithFilter("tcp port 80")(&o)
	if o.Promiscuous {
		t.Error("promiscuous should be false")
	}
	if o.SnapLen != 1500 {
		t.Error("snaplen not set")
	}
	if o.Filter != "tcp port 80" {
		t.Error("filter not set")
	}
}
