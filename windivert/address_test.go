//go:build windows

package windivert

import (
	"testing"
	"unsafe"
)

func TestAddressSize(t *testing.T) {
	if got := unsafe.Sizeof(Address{}); got != 88 {
		t.Errorf("Address size = %d, want 88", got)
	}
}

func TestAddressFlags(t *testing.T) {
	a := Address{
		Flags: (2 << 0) | // Layer = Flow
			(1 << 8) | // Event = 1
			(1 << 17) | // Outbound
			(1 << 20), // IPv6
	}
	if a.Layer() != LayerFlow { t.Errorf("Layer = %d, want %d", a.Layer(), LayerFlow) }
	if a.Event() != 1         { t.Errorf("Event = %d, want 1", a.Event()) }
	if !a.IsOutbound()        { t.Error("IsOutbound = false, want true") }
	if !a.IsIPv6()            { t.Error("IsIPv6 = false, want true") }
	if a.IsLoopback()         { t.Error("IsLoopback = true, want false") }
}
