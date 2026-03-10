//go:build linux

package afpacket

import (
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func readPacket(h *Handle) ([]byte, gopacket.CaptureInfo, error) {
	buf := make([]byte, h.opts.SnapLen)
	oob := make([]byte, 64)
	n, oobn, _, _, err := unix.Recvmsg(h.fd, buf, oob, 0)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}

	ts := time.Now()
	if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for _, msg := range msgs {
			if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SO_TIMESTAMP {
				if len(msg.Data) >= int(unsafe.Sizeof(unix.Timeval{})) {
					tv := (*unix.Timeval)(unsafe.Pointer(&msg.Data[0]))
					ts = time.Unix(tv.Sec, int64(tv.Usec)*1000)
				}
			}
		}
	}

	return buf[:n], gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: n,
		Length:        n,
	}, nil
}

func linkType() gopacket.Decoder { return layers.LayerTypeEthernet }
