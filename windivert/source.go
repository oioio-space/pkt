//go:build windows

package windivert

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ReadPacketData implements gopacket.PacketDataSource.
// It blocks until a packet is received from WinDivert.
func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	buf := make([]byte, h.opts.SnapLen)
	n, _, ts, err := h.Recv(buf)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	return buf[:n], gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: n,
		Length:        n,
	}, nil
}

// LinkType returns the gopacket decoder appropriate for the WinDivert layer.
// Network layers deliver raw IPv4/IPv6 packets (no Ethernet header).
func (h *Handle) LinkType() gopacket.Decoder {
	switch h.layer {
	case LayerNetwork, LayerNetworkForward:
		return layers.LayerTypeIPv4
	default:
		return layers.LayerTypeEthernet
	}
}
