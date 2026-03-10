//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"

	"pkt/windivert"
	"pkt/windivert/driver"
)

var installPersistent = flag.Bool("install-persistent", false,
	"installe WinDivert de façon permanente avec accès utilisateur, puis quitte (nécessite admin)")

func installHook() {} // flag enregistré via var ci-dessus

func runInstall() {
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
