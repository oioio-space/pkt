//go:build linux

package afpacket

import "golang.org/x/sys/unix"

func setPromiscuous(fd, ifIndex int, enable bool) error {
	mr := unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	opt := unix.PACKET_ADD_MEMBERSHIP
	if !enable {
		opt = unix.PACKET_DROP_MEMBERSHIP
	}
	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, opt, &mr)
}
