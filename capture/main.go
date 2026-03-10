package main

import (
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
)

func main() {
	iface  := flag.String("i", "", "network interface (required on Linux)")
	filter := flag.String("f", "", "filter: pcap-filter on Linux, WinDivert on Windows")
	count  := flag.Int("n", 0, "number of packets to capture (0 = unlimited)")
	flag.Parse()

	src, decoder, err := newSource(*iface, *filter)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var once sync.Once
	closeSrc := func() {
		once.Do(func() {
			if closer, ok := src.(io.Closer); ok {
				_ = closer.Close()
			}
		})
	}
	defer closeSrc()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		closeSrc()
	}()

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
