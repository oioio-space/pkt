//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/oioio-space/pkt/windivert"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	filterExpr := flag.String("f", "", "filtre WinDivert — paquets matchant ce filtre seront droppés")
	verbose := flag.Bool("v", false, "affiche les détails de chaque paquet droppé")
	flag.Parse()

	if *filterExpr == "" {
		fmt.Fprintln(os.Stderr, "flag -f requis (ex: -f \"tcp.DstPort == 443\")")
		os.Exit(1)
	}

	// Ouvre sans FlagSniff : les paquets matchant sont retenus par le noyau.
	// Ne pas appeler Send → ils sont droppés silencieusement.
	h, err := windivert.Open(*filterExpr, windivert.LayerNetwork)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer h.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ps := gopacket.NewPacketSource(h, h.LinkType())
	dropped := 0

	log.Printf("drop actif (filtre: %q) — Ctrl+C pour arrêter", *filterExpr)

loop:
	for {
		select {
		case <-ctx.Done():
			_ = h.Shutdown()
			break loop
		case pkt := <-ps.Packets():
			dropped++
			if *verbose {
				if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ip := ipLayer.(*layers.IPv4)
					log.Printf("drop #%d : %v → %v proto=%v size=%d",
						dropped, ip.SrcIP, ip.DstIP, ip.Protocol, len(pkt.Data()))
				} else {
					log.Printf("drop #%d : %d bytes", dropped, len(pkt.Data()))
				}
			}
			// Ne pas appeler h.Send → le noyau supprime le paquet
		}
	}

	log.Printf("terminé — %d paquets droppés", dropped)
}
