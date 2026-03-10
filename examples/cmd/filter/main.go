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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"pkt/windivert"
)

func main() {
	filterExpr := flag.String("f", "", "filtre WinDivert (ex: \"tcp.DstPort == 443\")")
	mode       := flag.String("mode", "blacklist", "blacklist: droppe ce qui matche | whitelist: laisse passer ce qui matche")
	verbose    := flag.Bool("v", false, "affiche les détails de chaque paquet droppé")
	flag.Parse()

	if *filterExpr == "" {
		fmt.Fprintln(os.Stderr, "flag -f requis")
		os.Exit(1)
	}
	if *mode != "blacklist" && *mode != "whitelist" {
		fmt.Fprintln(os.Stderr, "flag -mode doit être 'blacklist' ou 'whitelist'")
		os.Exit(1)
	}

	// En whitelist, on intercepte tout ce qui ne matche PAS le filtre et on le droppe.
	// Résultat : seul ce qui matche le filtre passe à travers.
	effectiveFilter := *filterExpr
	if *mode == "whitelist" {
		effectiveFilter = "not (" + *filterExpr + ")"
	}

	h, err := windivert.Open(effectiveFilter, windivert.LayerNetwork)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer h.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); h.Shutdown() }()

	ps := gopacket.NewPacketSource(h, h.LinkType())
	dropped := 0

	log.Printf("filtre actif [%s] (filtre WinDivert: %q) — Ctrl+C pour arrêter",
		*mode, effectiveFilter)

	for pkt := range ps.Packets() {
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
	log.Printf("terminé [%s] — %d paquets droppés", *mode, dropped)
}
