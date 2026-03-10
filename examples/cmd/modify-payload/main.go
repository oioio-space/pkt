//go:build windows

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"pkt/windivert"
)

func main() {
	filterExpr := flag.String("f", "tcp", "filtre WinDivert (ex: \"tcp.DstPort == 80\")")
	findStr    := flag.String("find", "", "texte à remplacer dans le payload TCP")
	replaceStr := flag.String("replace", "", "texte de remplacement")
	flag.Parse()

	if *findStr == "" {
		fmt.Fprintln(os.Stderr, "flag -find requis")
		os.Exit(1)
	}

	// Ouvre sans FlagSniff : WinDivert intercepte les paquets (le noyau les bloque)
	h, err := windivert.Open(*filterExpr, windivert.LayerNetwork)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer h.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); h.Shutdown() }()

	ps := gopacket.NewPacketSource(h, h.LinkType())
	find    := []byte(*findStr)
	replace := []byte(*replaceStr)
	modified, forwarded := 0, 0

	log.Printf("interception active (filtre: %q, find: %q → replace: %q)", *filterExpr, *findStr, *replaceStr)

	for pkt := range ps.Packets() {
		addr := windivert.AddressFromPacket(pkt)
		if addr == nil {
			continue
		}

		data := pkt.Data()
		ipLayer  := pkt.Layer(layers.LayerTypeIPv4)
		tcpLayer := pkt.Layer(layers.LayerTypeTCP)

		if ipLayer != nil && tcpLayer != nil && bytes.Contains(tcpLayer.(*layers.TCP).Payload, find) {
			ip  := ipLayer.(*layers.IPv4)
			tcp := tcpLayer.(*layers.TCP)
			tcp.Payload = bytes.ReplaceAll(tcp.Payload, find, replace)
			tcp.SetNetworkLayerForChecksum(ip)

			sbuf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
			if err := gopacket.SerializeLayers(sbuf, opts, ip, tcp, gopacket.Payload(tcp.Payload)); err != nil {
				log.Printf("serialize error: %v — forwarding original", err)
			} else {
				data = sbuf.Bytes()
				modified++
				log.Printf("modifié %d bytes (TCP %v:%d → %v:%d)",
					len(data), ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
			}
		} else {
			forwarded++
		}

		if err := h.Send(data, addr); err != nil {
			log.Printf("send error: %v", err)
		}
	}
	log.Printf("terminé — %d paquets modifiés, %d transférés", modified, forwarded)
}
