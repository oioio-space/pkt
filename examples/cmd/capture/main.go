package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/oioio-space/pkt/capture"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	iface := flag.String("i", "", "interface réseau (requis sur Linux)")
	filter := flag.String("f", "", "filtre de capture (WinDivert sur Windows, pcap-filter sur Linux)")
	count := flag.Int("n", 0, "nombre de paquets (0 = illimité)")
	outFile := flag.String("w", "", "fichier pcap de sortie (ex: out.pcap)")
	installHook() // Windows : enregistre -install-persistent ; no-op sur Linux
	flag.Parse()
	runInstall() // Windows : exécute l'installation si -install-persistent, puis quitte

	src, err := capture.Open(*iface, *filter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer src.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var pcapWriter *pcapgo.Writer
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return
		}
		defer f.Close()
		bw := bufio.NewWriterSize(f, 1<<20)
		defer bw.Flush()
		pcapWriter = pcapgo.NewWriter(bw)
		if err := pcapWriter.WriteFileHeader(65535, linkTypeToDLT(src.LinkType())); err != nil {
			fmt.Fprintln(os.Stderr, "pcap header:", err)
			return
		}
		log.Printf("écriture pcap dans %s", *outFile)
	}

	ps := gopacket.NewPacketSource(src, src.LinkType())
	captured := 0

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case pkt := <-ps.Packets():
			if pcapWriter != nil {
				ci := pkt.Metadata().CaptureInfo
				if err := pcapWriter.WritePacket(ci, pkt.Data()); err != nil {
					log.Printf("pcap write: %v", err)
				}
			} else {
				fmt.Println(pkt)
			}
			captured++
			if *count > 0 && captured >= *count {
				break loop
			}
		}
	}

	log.Printf("capturé %d paquets", captured)
}

// linkTypeToDLT mappe un gopacket.Decoder vers le DLT pcap correspondant.
func linkTypeToDLT(d gopacket.Decoder) layers.LinkType {
	switch d {
	case layers.LayerTypeIPv4:
		return layers.LinkTypeIPv4
	case layers.LayerTypeEthernet:
		return layers.LinkTypeEthernet
	default:
		return layers.LinkTypeEthernet
	}
}
