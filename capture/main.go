package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
)

func main() {
	iface  := flag.String("i", "", "network interface (required on Linux)")
	filter := flag.String("f", "", "filter: pcap-filter on Linux, WinDivert on Windows")
	count  := flag.Int("n", 0, "number of packets to capture (0 = unlimited)")
	flag.Parse()

	src, decoder, err := newSource(*iface, *filter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	ps := gopacket.NewPacketSource(src, decoder)
	captured := 0
	for pkt := range ps.Packets() {
		fmt.Println(pkt)
		captured++
		if *count > 0 && captured >= *count {
			break
		}
	}
	log.Printf("captured %d packets", captured)
}
