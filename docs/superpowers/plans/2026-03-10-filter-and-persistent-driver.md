# Filter Example + Persistent WinDivert Driver Installation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter un exemple `filter` (firewall whitelist/blacklist) et une installation WinDivert persistante via SCM avec ACL configurable.

**Architecture:** Deux fonctionnalités indépendantes. L'exemple `filter` exploite la puissance du filtre WinDivert natif pour implémenter blacklist/whitelist sans logique Go complexe : en mode blacklist le filtre est passé tel quel, en mode whitelist il est préfixé par `not (...)`. L'installation persistante ajoute des `InstallOption` fonctionnelles au package `driver` : `WithPersistent()` utilise `SERVICE_AUTO_START` + chemin stable dans `System32\drivers\`, `WithACL(sddl)` applique un DACL sur l'objet device après démarrage via `windows.SecurityDescriptorFromString` + `SetSecurityInfo`.

**Tech Stack:** Go 1.25, `pkt/windivert`, `golang.org/x/sys/windows`, `golang.org/x/sys/windows/svc/mgr`

---

## Chunk 1 : Exemple `filter` (whitelist/blacklist)

### Contexte fonctionnel

WinDivert intercepte les paquets **correspondant** à son filtre. Les paquets non-interceptés passent normalement. En n'appelant jamais `Send`, tous les paquets interceptés sont droppés.

- **Blacklist** `-mode blacklist -f "tcp.DstPort == 443"` :
  WinDivert ouvre avec le filtre tel quel → tout ce qui matche est droppé → HTTPS bloqué.

- **Whitelist** `-mode whitelist -f "tcp.DstPort == 443"` :
  WinDivert ouvre avec `not (tcp.DstPort == 443)` → tout ce qui ne matche PAS le filtre est droppé → seul HTTPS passe.

Pas de logique de matching en Go — WinDivert fait tout le travail au niveau kernel.

---

### Task 1 : Exemple `filter` Windows

**Files:**
- Create: `examples/cmd/filter/main.go`

**Comportement :**
- Flags : `-f` (filtre WinDivert, requis), `-mode blacklist|whitelist` (défaut : blacklist), `-v` (verbose)
- Construit le filtre WinDivert effectif selon le mode :
  - blacklist → filtre = `-f` directement
  - whitelist → filtre = `"not (" + f + ")"`
- Ouvre WinDivert sans `FlagSniff` (interception réelle)
- Loop : `Recv` → si `-v` log src→dst proto size → **ne jamais Send** → le noyau droppe
- Sur Ctrl+C : `Shutdown` + `Close` + log stats (dropped + mode)

- [ ] **Step 1 : Créer `examples/cmd/filter/main.go`**

```go
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
	mode       := flag.String("mode", "blacklist", "mode: blacklist (droppe ce qui matche) ou whitelist (laisse passer ce qui matche)")
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

	buf := make([]byte, 65535)
	dropped := 0

	log.Printf("filtre actif [%s] (filtre WinDivert: %q) — Ctrl+C pour arrêter",
		*mode, effectiveFilter)

	for {
		n, _, _, err := h.Recv(buf)
		if err != nil {
			break
		}
		dropped++

		if *verbose {
			pkt := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
			if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)
				log.Printf("drop #%d : %v → %v proto=%v size=%d",
					dropped, ip.SrcIP, ip.DstIP, ip.Protocol, n)
			} else {
				log.Printf("drop #%d : %d bytes", dropped, n)
			}
		}
		// Ne pas appeler h.Send → le noyau supprime le paquet
	}
	log.Printf("terminé [%s] — %d paquets droppés", *mode, dropped)
}
```

- [ ] **Step 2 : Build check**

```bash
cd /c/Users/m.bachmann/GolandProjects/pkt
GOOS=windows go build ./examples/cmd/filter/
```
Résultat attendu : pas d'erreur.

- [ ] **Step 3 : Commit**

```bash
git add examples/cmd/filter/
git commit -m "feat(examples/filter): whitelist/blacklist firewall using WinDivert filter inversion"
```

---

### Task 2 : Mettre à jour Makefile et build.ps1 pour l'exemple filter

**Files:**
- Modify: `Makefile`
- Modify: `build.ps1`

- [ ] **Step 1 : Lire Makefile actuel**

```bash
cat /c/Users/m.bachmann/GolandProjects/pkt/Makefile
```

- [ ] **Step 2 : Ajouter la cible filter dans Makefile**

Ajouter dans la section variables :
```makefile
WINDOWS_FILTER  := $(DIST)/filter-windows-amd64.exe
```

Modifier la cible `windows:` pour inclure le binaire filter :
```makefile
windows: $(DIST)
	GOOS=windows go build -trimpath -o $(WINDOWS_CAPTURE) ./examples/cmd/capture/
	GOOS=windows go build -trimpath -o $(WINDOWS_MODIFY)  ./examples/cmd/modify-payload/
	GOOS=windows go build -trimpath -o $(WINDOWS_DROP)    ./examples/cmd/drop/
	GOOS=windows go build -trimpath -o $(WINDOWS_FILTER)  ./examples/cmd/filter/
	@$(ECHO) Built: $(WINDOWS_CAPTURE) $(WINDOWS_MODIFY) $(WINDOWS_DROP) $(WINDOWS_FILTER)
```

- [ ] **Step 3 : Ajouter filter dans build.ps1**

Dans `Build-Windows`, ajouter :
```powershell
$outFilter = Join-Path $dist "filter-windows-amd64.exe"
Write-Host "Building Windows filter..."
go build -trimpath -o $outFilter ./examples/cmd/filter/
Write-Host "Built: $outFilter"
```

- [ ] **Step 4 : Commit**

```bash
git add Makefile build.ps1
git commit -m "chore: add filter example to Makefile and build.ps1"
```

---

## Chunk 2 : Installation WinDivert persistante + ACL

### Contexte technique

#### Installation actuelle (temporaire)
`installService` crée le service avec `mgr.StartManual`, le démarre, puis appelle immédiatement `s.Delete()`. Cela correspond au comportement de la DLL WinDivert officielle : le service est marqué pour suppression automatique quand le dernier handle est fermé. Le `.sys` est extrait dans un dossier temp (`os.MkdirTemp`).

**Problème** : À chaque redémarrage, le service est supprimé → il faut être admin au prochain lancement.

#### Installation persistante
- **Chemin stable** : `%SystemRoot%\System32\drivers\WinDivert64.sys` (comme les vrais drivers)
- **StartType** : `mgr.StartAutomatic` (démarre au boot) ou `mgr.StartManual` sans `Delete()`
- **Pas de Delete** : le service survit

#### ACL sur l'objet device
WinDivert crée l'objet device `\\.\WinDivert` avec une security descriptor restrictive (admins seuls). Pour autoriser des processus non-admin à l'utiliser, on modifie son DACL après démarrage du service :

```
SDDL: "D:(A;;GA;;;AU)"   → Authenticated Users : GENERIC_ALL
SDDL: "D:(A;;GA;;;WD)"   → Everyone (World) : GENERIC_ALL
SDDL: "D:(A;;GA;;;BA)(A;;GA;;;AU)" → Admins + Authenticated Users
```

API Windows :
```go
sd, err := windows.SecurityDescriptorFromString(sddl)
dacl, _, err := sd.DACL()
handle, err := driver.OpenDevice()
windows.SetSecurityInfo(handle, windows.SE_KERNEL_OBJECT,
    windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
```

> Note : modifier la DACL du device WinDivert nécessite toujours des privilèges admin lors de l'installation initiale. Ensuite, les utilisateurs sans droits admin peuvent ouvrir le device.

### Task 3 : Options fonctionnelles + installation persistante

**Files:**
- Modify: `windivert/driver/installer.go`

L'API publique devient :
```go
// WithPersistent installe le service de façon permanente (AUTO_START, chemin stable).
// Sans cette option, le comportement est identique à avant (DEMAND_START, temp dir, Delete immédiat).
func WithPersistent() InstallOption

// Install installe le driver WinDivert via SCM.
// Sans options : comportement inchangé (temporaire, compatible avec l'existant).
// Avec WithPersistent() : chemin stable, pas de Delete, démarrage automatique.
func Install(sysData []byte, opts ...InstallOption) error
```

- [ ] **Step 1 : Écrire le test de compilation des nouvelles options**

Dans un nouveau fichier `windivert/driver/installer_test.go` :

```go
//go:build windows

package driver

import "testing"

// TestInstallOptionsCompile vérifie que WithPersistent et WithACL compilent.
func TestInstallOptionsCompile(t *testing.T) {
	opts := []InstallOption{
		WithPersistent(),
	}
	_ = opts
}
```

- [ ] **Step 2 : Vérifier que le test échoue (types absent)**

```bash
cd /c/Users/m.bachmann/GolandProjects/pkt
GOOS=windows go build ./windivert/driver/...
```
Résultat attendu : erreur "undefined: InstallOption" ou similaire.

- [ ] **Step 3 : Implémenter `WithPersistent` et modifier `Install`**

Modifier `windivert/driver/installer.go` — remplacer le contenu par :

```go
//go:build windows

// Package driver installe et gère le driver kernel WinDivert via SCM.
package driver

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WinDivert"

// installConfig regroupe les options d'installation.
type installConfig struct {
	persistent bool   // true = SERVICE_AUTO_START + chemin stable + pas de Delete
	aclSDDL    string // SDDL DACL à appliquer sur le device après démarrage (vide = inchangé)
}

// InstallOption configure l'installation du driver.
type InstallOption func(*installConfig)

// WithPersistent installe le driver de façon permanente :
//   - Chemin stable : %SystemRoot%\System32\drivers\WinDivert64.sys
//   - StartType SERVICE_AUTO_START (démarre au boot)
//   - Le service n'est PAS marqué pour suppression automatique
//
// Sans cette option (défaut) : comportement temporaire identique à la DLL officielle
// (temp dir, StartManual, Delete immédiat après démarrage).
func WithPersistent() InstallOption {
	return func(c *installConfig) { c.persistent = true }
}

// WithACL applique un DACL personnalisé sur l'objet device WinDivert après démarrage.
// sddl est une chaîne SDDL décrivant le DACL, ex : "D:(A;;GA;;;AU)" pour
// autoriser Authenticated Users à ouvrir le device sans droits admin.
//
// Cette opération nécessite des privilèges admin lors de son application initiale.
// Une fois le DACL positionné, les processus non-admin peuvent ouvrir le device.
func WithACL(sddl string) InstallOption {
	return func(c *installConfig) { c.aclSDDL = sddl }
}

// WithUserAccess est un raccourci pour WithACL qui autorise tous les utilisateurs
// authentifiés (Authenticated Users, SID AU) à utiliser le driver WinDivert
// sans droits administrateur.
func WithUserAccess() InstallOption {
	return WithACL("D:(A;;GA;;;AU)")
}

// Install extrait le binaire .sys et installe le driver WinDivert via SCM.
// Sans options : comportement inchangé (temporaire, compatible avec l'existant).
func Install(sysData []byte, opts ...InstallOption) error {
	cfg := &installConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	sysPath, err := extractSys(sysData, cfg.persistent)
	if err != nil {
		return fmt.Errorf("extract sys: %w", err)
	}

	if err := installService(sysPath, cfg); err != nil {
		return err
	}

	if cfg.aclSDDL != "" {
		if err := applyDeviceACL(cfg.aclSDDL); err != nil {
			return fmt.Errorf("apply ACL: %w", err)
		}
	}
	return nil
}

// Uninstall arrête et supprime le service SCM WinDivert.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // non installé
	}
	defer s.Close()
	_, _ = s.Control(windows.SERVICE_CONTROL_STOP)
	return s.Delete()
}

// OpenDevice ouvre le device WinDivert et retourne un handle Windows compatible overlapped.
func OpenDevice() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(`\\.\WinDivert`)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
}

// extractSys écrit le binaire .sys dans un chemin approprié.
// persistent=true → chemin stable dans %SystemRoot%\System32\drivers\.
// persistent=false → répertoire temporaire (comportement existant).
func extractSys(data []byte, persistent bool) (string, error) {
	if persistent {
		return extractSysStable(data)
	}
	dir, err := os.MkdirTemp("", "windivert-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "WinDivert64.sys")
	return path, os.WriteFile(path, data, 0600)
}

// extractSysStable écrit WinDivert64.sys dans %SystemRoot%\System32\drivers\.
// Si le fichier existe déjà (installation précédente), il est réutilisé tel quel.
func extractSysStable(data []byte) (string, error) {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	path := filepath.Join(sysRoot, "System32", "drivers", "WinDivert64.sys")
	// Si déjà présent, ne pas écraser (le driver pourrait être en cours d'utilisation).
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return path, os.WriteFile(path, data, 0600)
}

func installService(sysPath string, cfg *installConfig) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM connect: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		return startIfStopped(s)
	}

	startType := mgr.StartManual
	if cfg.persistent {
		startType = mgr.StartAutomatic
	}

	s, err = m.CreateService(serviceName, sysPath, mgr.Config{
		ServiceType:  windows.SERVICE_KERNEL_DRIVER,
		StartType:    startType,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "WinDivert Network Driver",
	})
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return err
	}

	if !cfg.persistent {
		// Comportement temporaire : marquer pour suppression automatique
		// quand le dernier handle WinDivert est fermé (comme la DLL officielle).
		_ = s.Delete()
	}
	return nil
}

func startIfStopped(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == windows.SERVICE_RUNNING {
		return nil
	}
	return s.Start()
}

// applyDeviceACL applique un DACL SDDL sur l'objet kernel device WinDivert.
// Nécessite des privilèges admin.
func applyDeviceACL(sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL %q: %w", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract DACL: %w", err)
	}

	h, err := OpenDevice()
	if err != nil {
		return fmt.Errorf("open device: %w", err)
	}
	defer windows.CloseHandle(h)

	return windows.SetSecurityInfo(
		h,
		windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
```

- [ ] **Step 4 : Build check**

```bash
cd /c/Users/m.bachmann/GolandProjects/pkt
GOOS=windows go build ./windivert/...
GOOS=windows go vet ./windivert/...
```
Résultat attendu : 0 erreur.

- [ ] **Step 5 : Vérifier que le test compile**

```bash
GOOS=windows go test -run TestInstallOptionsCompile ./windivert/driver/...
```
Résultat attendu : PASS (test compile-time uniquement).

- [ ] **Step 6 : Vérifier que windivert.go appelle toujours Install correctement**

`windivert/windivert.go` appelle `driver.Install(assets.Sys64)` sans options — la signature est maintenant `Install(sysData []byte, opts ...InstallOption)` donc l'appel existant reste valide (variadic = 0 opts = comportement inchangé).

```bash
GOOS=windows go build ./windivert/...
```
Résultat attendu : pas d'erreur.

- [ ] **Step 7 : Commit**

```bash
git add windivert/driver/installer.go windivert/driver/installer_test.go
git commit -m "feat(windivert/driver): persistent SCM install + user ACL via WithPersistent/WithACL/WithUserAccess"
```

---

### Task 4 : Exposer les options dans l'API publique `windivert`

**Files:**
- Modify: `windivert/windivert.go`

Actuellement, `windivert.Open()` appelle `driver.Install(assets.Sys64)` en dur. On veut exposer les options d'installation sans les faire remonter dans `Open()` (qui gère l'ouverture d'un handle, pas l'installation globale). L'installation persistante est une opération one-shot distincte.

On ajoute une fonction `windivert.InstallDriver(opts ...driver.InstallOption) error` pour les utilisateurs qui veulent contrôler l'installation.

- [ ] **Step 1 : Ajouter `InstallDriver` dans `windivert/windivert.go`**

Ajouter après les imports existants (ne pas modifier `Open`) :

```go
// InstallDriver installe le driver WinDivert via SCM avec les options données.
// Sans options : comportement temporaire (compatible avec Open).
// Avec driver.WithPersistent() : installation permanente (survit aux redémarrages).
// Avec driver.WithUserAccess() ou driver.WithACL(sddl) : permet l'accès sans droits admin.
//
// Exemple — installation permanente pour tous les utilisateurs authentifiés :
//
//	err := windivert.InstallDriver(driver.WithPersistent(), driver.WithUserAccess())
func InstallDriver(opts ...driver.InstallOption) error {
	return driver.Install(assets.Sys64, opts...)
}
```

Et ajouter `"pkt/windivert/driver"` aux imports de `windivert/windivert.go`.

- [ ] **Step 2 : Build check**

```bash
GOOS=windows go build ./windivert/...
```

- [ ] **Step 3 : Commit**

```bash
git add windivert/windivert.go
git commit -m "feat(windivert): expose InstallDriver() with persistent/ACL options"
```

---

### Task 5 : Mettre à jour l'exemple `capture` pour documenter l'installation persistante

**Files:**
- Modify: `examples/cmd/capture/main.go` (ajouter flag `-install-persistent`)

L'exemple `capture` est le point d'entrée le plus naturel pour montrer l'installation persistante. On ajoute un flag `-install` qui fait uniquement l'installation et quitte.

- [ ] **Step 1 : Modifier `examples/cmd/capture/source_windows.go`**

Ajouter un flag `installPersistent` dans le main. Attention : `source_windows.go` expose `newSource` — le flag doit être dans `main.go`.

Modifier `examples/cmd/capture/main.go` : ajouter après les imports :

```go
// Flags supplémentaires Windows uniquement (déclarés dans main, utilisés conditionnellement)
```

Et dans `main()`, avant `flag.Parse()` :

Note : pour éviter des dépendances conditionnelles à la compilation dans `main.go` (qui est cross-platform), on garde le flag d'installation dans `source_windows.go` et on crée un hook `installHook()` avec stubs platform.

Structure propre :
- `source_windows.go` : ajoute flag `-install-persistent`, définit `installHook()`
- `source_linux.go` : ajoute stub `installHook() {}`

- [ ] **Step 2 : Modifier `examples/cmd/capture/source_windows.go`**

```go
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
```

- [ ] **Step 3 : Ajouter stub `installHook` dans `source_linux.go`**

Ajouter à la fin de `examples/cmd/capture/source_linux.go` :

```go
// installHook est un no-op sur Linux (installation persistante = Windows uniquement).
func installHook() {}
```

- [ ] **Step 4 : Appeler `installHook()` dans `main.go`**

Dans `examples/cmd/capture/main.go`, ajouter après `flag.Parse()` :

```go
	installHook() // Windows : handle -install-persistent flag
```

- [ ] **Step 5 : Build check**

```bash
GOOS=windows go build ./examples/cmd/capture/
GOOS=linux   go build ./examples/cmd/capture/
```

- [ ] **Step 6 : Commit**

```bash
git add examples/cmd/capture/
git commit -m "feat(examples/capture): add -install-persistent flag for permanent WinDivert setup"
```

---

## Notes d'implémentation

### Pourquoi `not (...)` pour la whitelist

WinDivert ne supporte pas l'interception de "tout sauf X" directement comme un seul handle — mais supporte la négation dans les filtres. `not (expr)` est syntaxiquement valide dans WinDivert 2.x.

Alternative non retenue : deux handles (un pour le trafic à dropper, un pour le reste) — plus complexe, même résultat.

### Chemin stable du .sys

`%SystemRoot%\System32\drivers\WinDivert64.sys` est le chemin standard des drivers kernel Windows. Le SCM (Services Control Manager) lit ce chemin depuis le registre au boot pour démarrer le service automatiquement. Un chemin temporaire (`MkdirTemp`) serait détruit à chaque redémarrage → le service auto-start échouerait.

### `windows.SecurityDescriptorFromString` et DACL

`SecurityDescriptorFromString` parse un SDDL, `sd.DACL()` extrait le `*windows.ACL`. `SetSecurityInfo` avec `SE_KERNEL_OBJECT` applique le DACL à l'objet kernel du device. Cette opération nécessite `SeSecurityPrivilege` (inclus dans les droits admin).

### `Open()` reste inchangé

`windivert.Open()` continue d'appeler `driver.Install(assets.Sys64)` sans options — l'installation temporaire reste le défaut. Les utilisateurs qui veulent l'installation persistante appellent `windivert.InstallDriver(...)` séparément avant `Open()`.
