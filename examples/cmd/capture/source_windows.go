//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"pkt/windivert"
	"pkt/windivert/driver"
)

var installPersistent = flag.Bool("install-persistent", false,
	"installe WinDivert de façon permanente avec accès utilisateur, puis quitte (nécessite admin)")

func installHook() {
	if !*installPersistent {
		return
	}
	fmt.Println("Installation persistante de WinDivert avec accès utilisateur...")
	if err := windivert.InstallDriver(driver.WithPersistent(), driver.WithUserAccess()); err != nil {
		fmt.Fprintln(os.Stderr, "erreur:", err)
		os.Exit(1)
	}
	fmt.Println("Installation réussie. Le driver démarrera automatiquement au prochain boot.")
	os.Exit(0)
}

func newSource(_ string, filterExpr string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	if filterExpr == "" {
		filterExpr = "true"
	}
	h, err := windivert.Open(filterExpr, windivert.LayerNetwork, windivert.WithFlags(windivert.FlagSniff))
	if err != nil {
		return nil, nil, err
	}
	return h, h.LinkType(), nil
}
