//go:build windows

package windivert

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ReadPacketData implements gopacket.PacketDataSource.
// The returned slice is a copy — safe to hold across calls.
// The *Address is available via AddressFromPacket(pkt).
func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	n, addr, ts, err := h.Recv(h.recvBuf)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	pktCopy := make([]byte, n)
	copy(pktCopy, h.recvBuf[:n])
	return pktCopy, gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: n,
		Length:        n,
		AncillaryData: []interface{}{addr},
	}, nil
}

// AddressFromPacket extracts the WinDivert *Address from a gopacket.Packet.
// Returns nil if the address is not present (non-WinDivert source).
func AddressFromPacket(pkt gopacket.Packet) *Address {
	for _, v := range pkt.Metadata().CaptureInfo.AncillaryData {
		if addr, ok := v.(*Address); ok {
			return addr
		}
	}
	return nil
}

// LinkType returns the gopacket decoder appropriate for the WinDivert layer.
func (h *Handle) LinkType() gopacket.Decoder {
	switch h.layer {
	case LayerNetwork, LayerNetworkForward:
		return layers.LayerTypeIPv4
	default:
		return layers.LayerTypeEthernet
	}
}
