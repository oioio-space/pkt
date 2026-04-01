// Package windivert provides a Go interface to the WinDivert 2.x kernel driver,
// enabling userspace interception, inspection, modification, and re-injection
// of network packets on Windows.
//
// WinDivert hooks into the Windows Filtering Platform (WFP) and captures all
// IP traffic on the machine — no promiscuous mode required. The embedded
// WinDivert64.sys driver is extracted and installed automatically on first use.
//
// It implements gopacket.PacketDataSource and is compatible with gopacket's
// decoding and packet-source APIs.
//
// # Usage
//
//	h, err := windivert.Open("tcp.DstPort == 443", windivert.LayerNetwork)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer h.Close()
//	ps := gopacket.NewPacketSource(h, h.LinkType())
//	for pkt := range ps.Packets() {
//	    addr := windivert.AddressFromPacket(pkt)
//	    // inspect, modify, then re-inject:
//	    if err := h.Send(pkt.Data(), addr); err != nil {
//	        log.Println("send:", err)
//	    }
//	}
//
// # Requirements
//
// Windows only. Requires administrator privileges — WinDivert enforces this
// via its device DACL (SDDL_DEVOBJ_SYS_ALL_ADM_ALL).
package windivert
