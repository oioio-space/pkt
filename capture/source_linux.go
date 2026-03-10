//go:build linux

package main

import (
	"github.com/google/gopacket"
	"pkt/afpacket"
)

func newSource(iface, filterExpr string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	opts := []afpacket.Option{afpacket.WithPromiscuous(true)}
	if filterExpr != "" {
		opts = append(opts, afpacket.WithFilter(filterExpr))
	}
	h, err := afpacket.Open(iface, opts...)
	if err != nil {
		return nil, nil, err
	}
	return h, h.LinkType(), nil
}
