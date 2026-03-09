//go:build windows

package main

import (
	"github.com/google/gopacket"
	"pkt/windivert"
)

func newSource(_ string, filterExpr string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	if filterExpr == "" {
		filterExpr = "true" // capture all packets
	}
	h, err := windivert.Open(filterExpr, windivert.LayerNetwork)
	if err != nil {
		return nil, nil, err
	}
	return h, h.LinkType(), nil
}
