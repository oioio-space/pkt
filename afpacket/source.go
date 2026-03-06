//go:build linux

package afpacket

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func readPacket(h *Handle) ([]byte, gopacket.CaptureInfo, error) {
	buf := make([]byte, h.opts.SnapLen)
	n, _, err := unix.Recvfrom(h.fd, buf, 0)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	return buf[:n], gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: n,
		Length:        n,
	}, nil
}

func linkType() gopacket.Decoder { return layers.LayerTypeEthernet }
