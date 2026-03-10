//go:build linux

package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"pkt/afpacket"
)

func newSource(iface string, filterExpr string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	if iface == "" {
		return nil, nil, fmt.Errorf("flag -i requis sur Linux")
	}
	opts := []afpacket.Option{afpacket.WithPromiscuous(true)}
	if filterExpr != "" {
		opts = append(opts, afpacket.WithFilter(filterExpr))
	}
	h, err := afpacket.Open(iface, opts...)
	if err != nil {
		return nil, nil, err
	}
	return h, layers.LayerTypeEthernet, nil
}
