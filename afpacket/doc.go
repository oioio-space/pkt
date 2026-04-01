// Package afpacket provides a Linux AF_PACKET packet capture source
// compatible with gopacket.PacketDataSource.
//
// It opens a raw socket on the specified network interface with optional
// kernel-level BPF filtering, promiscuous mode, and SO_TIMESTAMP precision.
//
// # Usage
//
//	h, err := afpacket.Open("eth0",
//	    afpacket.WithPromiscuous(true),
//	    afpacket.WithFilter("tcp port 80"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer h.Close()
//	ps := gopacket.NewPacketSource(h, h.LinkType())
//	for pkt := range ps.Packets() {
//	    fmt.Println(pkt)
//	}
//
// # Requirements
//
// Linux only. Requires root or CAP_NET_RAW capability.
package afpacket
