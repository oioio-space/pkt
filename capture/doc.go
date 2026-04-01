// Package capture provides a cross-platform packet capture API backed by
// WinDivert on Windows and AF_PACKET on Linux.
//
// A single [Open] call returns a [Source] that implements
// gopacket.PacketDataSource on both platforms.
//
// Filter syntax is platform-specific:
//   - Windows: WinDivert 2.x expression (e.g. "tcp.DstPort == 443")
//   - Linux:   pcap-filter expression    (e.g. "tcp port 443")
//
// # Usage
//
//	src, err := capture.Open("eth0", "tcp port 443") // iface ignored on Windows
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer src.Close()
//	ps := gopacket.NewPacketSource(src, src.LinkType())
//	for pkt := range ps.Packets() {
//	    fmt.Println(pkt)
//	}
//
// # Requirements
//
// Windows: administrator privileges (WinDivert requirement).
// Linux: root or CAP_NET_RAW capability.
package capture
