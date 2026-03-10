//go:build linux

package afpacket

import (
	"golang.org/x/sys/unix"
)

// Send injecte un paquet brut sur l'interface associée au Handle.
// Note : AF_PACKET ne peut pas bloquer le trafic — Send effectue une injection,
// pas une réinjection après interception. Les paquets originaux continuent de circuler.
// Le socket doit avoir été préalablement lié via Open() (qui appelle bind).
func (h *Handle) Send(pkt []byte) error {
	sll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  h.ifindex,
		Hatype:   unix.ARPHRD_ETHER,
		Pkttype:  unix.PACKET_OUTGOING,
	}
	return unix.Sendto(h.fd, pkt, 0, &sll)
}
