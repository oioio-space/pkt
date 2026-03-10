package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	iface   := flag.String("i", "", "interface réseau (requis sur Linux)")
	filter  := flag.String("f", "", "filtre: pcap-filter (Linux) ou WinDivert (Windows)")
	count   := flag.Int("n", 0, "nombre de paquets (0 = illimité)")
	outFile := flag.String("w", "", "fichier pcap de sortie (ex: out.pcap)")
	flag.Parse()

	installHook() // Windows: gère -install-persistent; no-op sur Linux

	src, decoder, err := newSource(*iface, *filter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var once sync.Once
	closeSrc := func() {
		once.Do(func() {
			if c, ok := src.(io.Closer); ok {
				_ = c.Close()
			}
		})
	}
	defer closeSrc()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); closeSrc() }()

	// Sortie pcap optionnelle
	var pcapWriter *pcapgo.Writer
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		bw := bufio.NewWriterSize(f, 1<<20) // 1 MiB write buffer
		defer bw.Flush()
		lt := layerTypeToLinkType(decoder)
		pcapWriter = pcapgo.NewWriter(bw)
		if err := pcapWriter.WriteFileHeader(65535, lt); err != nil {
			fmt.Fprintln(os.Stderr, "pcap header:", err)
			os.Exit(1)
		}
		log.Printf("écriture pcap dans %s", *outFile)
	}

	ps := gopacket.NewPacketSource(src, decoder)
	captured := 0
	for pkt := range ps.Packets() {
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
			break
		}
	}
	log.Printf("capturé %d paquets", captured)
}

// layerTypeToLinkType maps a gopacket.Decoder (LayerType) to the
// corresponding pcap DLT (layers.LinkType) for the pcap file header.
func layerTypeToLinkType(d gopacket.Decoder) layers.LinkType {
	switch d {
	case layers.LayerTypeIPv4:
		return layers.LinkTypeIPv4 // DLT 228 — raw IPv4 (WinDivert LayerNetwork)
	case layers.LayerTypeEthernet:
		return layers.LinkTypeEthernet
	default:
		return layers.LinkTypeEthernet
	}
}
