# Examples Packets Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Créer un dossier `examples/` avec 3 programmes Go démontrant capture (+ pcap), modification de payload TCP, et drop de paquets — en ajoutant `Send()` à afpacket et en restructurant le module workspace.

**Architecture:** Le module `capture/` est remplacé par `examples/` (module `pkt/examples`) contenant trois sous-commandes dans `cmd/`. WinDivert (Windows) gère l'interception réelle (modify + drop) en ouvrant sans `FlagSniff`. AF_PACKET (Linux) reçoit `Send()` via `unix.Sendto()` pour l'injection (pas d'interception noyau). Le pcap est généré via `gopacket/pcapgo`.

**Tech Stack:** Go 1.25, `github.com/google/gopacket` (gopacket + pcapgo + layers), `pkt/windivert`, `pkt/afpacket`, `golang.org/x/sys/unix`

---

## Chunk 1 : afpacket Send + exemples capture et modify-payload

### Task 1 : Ajouter `Send()` à afpacket (Linux)

**Files:**
- Modify: `afpacket/afpacket.go`
- Create: `afpacket/send_linux.go`
- Modify: `afpacket/afpacket_test.go` (test de compilation/signature uniquement)

- [ ] **Step 1 : Écrire le test de signature**

Dans `afpacket/afpacket_test.go`, ajouter à la fin :

```go
func TestHandleSendExists(t *testing.T) {
	// Vérifie que Send compile — pas d'exécution réseau requise.
	var h *Handle
	_ = (*Handle).Send // compile-time check
	_ = h
}
```

- [ ] **Step 2 : Vérifier que le test échoue (méthode absente)**

```bash
cd /c/Users/m.bachmann/GolandProjects/pkt/afpacket
go build ./...
```
Résultat attendu : succès de compilation (la méthode n'est pas encore là, mais le test est syntaxiquement valide).

> Note : on ne peut pas exécuter les tests Linux sur Windows — on vérifie la compilation cross en passant GOOS=linux.

```bash
GOOS=linux go build ./...
```
Résultat attendu : OK (le test référence `(*Handle).Send` qui n'existe pas encore → **échec** attendu ici).

- [ ] **Step 3 : Implémenter `Send()` dans `afpacket/send_linux.go`**

```go
//go:build linux

package afpacket

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Send injecte un paquet brut sur l'interface associée au Handle.
// Note : AF_PACKET ne peut pas bloquer le trafic — Send effectue une injection,
// pas une réinjection après interception. Les paquets originaux continuent de circuler.
func (h *Handle) Send(data []byte) error {
	sll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  0, // 0 = interface liée au socket
		Hatype:   unix.ARPHRD_ETHER,
		Pkttype:  unix.PACKET_OUTGOING,
	}
	if err := unix.Sendto(h.fd, data, 0, &sll); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}
```

- [ ] **Step 4 : Vérifier que ça compile**

```bash
GOOS=linux go build ./...
```
Résultat attendu : OK, pas d'erreur.

- [ ] **Step 5 : Commit**

```bash
git add afpacket/send_linux.go afpacket/afpacket_test.go
git commit -m "feat(afpacket): add Send() via unix.Sendto for raw packet injection"
```

---

### Task 2 : Créer le module `examples/` et restructurer le workspace

**Files:**
- Create: `examples/go.mod`
- Create: `examples/go.sum` (généré)
- Modify: `go.work` (remplacer `./capture` par `./examples`)

- [ ] **Step 1 : Créer `examples/go.mod`**

```
module pkt/examples

go 1.25.0

require (
	github.com/google/gopacket v1.1.19
	pkt/afpacket v0.0.0
	pkt/windivert v0.0.0
)

require (
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859 // indirect
	golang.org/x/sys v0.0.0-20190412213103-97732733099d // indirect
)

replace (
	pkt/afpacket => ../afpacket
	pkt/windivert => ../windivert
)
```

> Les versions exactes de `require` seront mises à jour par `go mod tidy`.

- [ ] **Step 2 : Mettre à jour `go.work`**

Remplacer `./capture` par `./examples` :

```
go 1.26.1

use (
	./afpacket
	./bpf
	./examples
	./windivert
)
```

- [ ] **Step 3 : Créer les répertoires**

```bash
mkdir -p /c/Users/m.bachmann/GolandProjects/pkt/examples/cmd/capture
mkdir -p /c/Users/m.bachmann/GolandProjects/pkt/examples/cmd/modify-payload
mkdir -p /c/Users/m.bachmann/GolandProjects/pkt/examples/cmd/drop
```

- [ ] **Step 4 : Résoudre les dépendances**

```bash
cd /c/Users/m.bachmann/GolandProjects/pkt/examples
go mod tidy
```
Résultat attendu : `go.sum` généré, pas d'erreur.

- [ ] **Step 5 : Commit structure**

```bash
git add examples/go.mod examples/go.sum go.work
git commit -m "chore: add examples module, replace capture in go.work"
```

---

### Task 3 : Exemple `capture` (avec export pcap)

**Files:**
- Create: `examples/cmd/capture/main.go`
- Create: `examples/cmd/capture/source_linux.go`
- Create: `examples/cmd/capture/source_windows.go`

**Comportement :**
- Flags : `-i` interface, `-f` filtre, `-n` nombre de paquets, `-w` fichier pcap de sortie
- Sans `-w` : affiche les paquets sur stdout (comportement actuel)
- Avec `-w` : écrit un fichier `.pcap` lisible par Wireshark via `pcapgo.NewWriter`

- [ ] **Step 1 : Créer `examples/cmd/capture/source_windows.go`**

```go
//go:build windows

package main

import (
	"github.com/google/gopacket"
	"pkt/windivert"
)

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

- [ ] **Step 2 : Créer `examples/cmd/capture/source_linux.go`**

```go
//go:build linux

package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"pkt/afpacket"
)

func newSource(iface string, filterExpr string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	if iface == "" {
		return nil, nil, fmt.Errorf("flag -i requis sur Linux")
	}
	opts := []afpacket.Option{afpacket.WithPromiscuous(true)}
	if filterExpr != "" {
		opts = append(opts, afpacket.WithFilter(filterExpr))
	}
	h, err := afpacket.Open(iface, opts...)
	if err != nil {
		return nil, nil, err
	}
	return h, layers.LayerTypeEthernet, nil
}
```

- [ ] **Step 3 : Créer `examples/cmd/capture/main.go`**

```go
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
	"github.com/google/gopacket/pcapgo"
)

func main() {
	iface   := flag.String("i", "", "interface réseau (requis sur Linux)")
	filter  := flag.String("f", "", "filtre: pcap-filter (Linux) ou WinDivert (Windows)")
	count   := flag.Int("n", 0, "nombre de paquets (0 = illimité)")
	outFile := flag.String("w", "", "écrire un fichier pcap (ex: out.pcap)")
	flag.Parse()

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

	// Optionnel : sortie pcap
	var pcapWriter *pcapgo.Writer
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		pcapWriter = pcapgo.NewWriter(f)
		if err := pcapWriter.WriteFileHeader(65535, decoder.(interface{ LayerType() interface{} })); err != nil {
			// Fallback : utiliser Ethernet linktype (1)
			_ = err
		}
	}

	ps := gopacket.NewPacketSource(src, decoder)
	captured := 0
	for pkt := range ps.Packets() {
		if pcapWriter != nil {
			ci := pkt.Metadata().CaptureInfo
			if err := pcapWriter.WritePacket(ci, pkt.Data()); err != nil {
				log.Printf("pcap write error: %v", err)
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
```

> **Note sur le LinkType pcap :** `pcapgo.NewWriter` puis `WriteFileHeader` prend un `layers.LinkType`. Le decoder (gopacket.Decoder) est aussi un `layers.LinkType` — on le cast directement.

- [ ] **Step 4 : Corriger le pcap WriteFileHeader** — remplacer le bloc pcap par :

```go
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		pcapWriter = pcapgo.NewWriter(f)
		lt, ok := decoder.(interface{ LayerType() gopacket.LayerType })
		_ = ok
		// gopacket.Decoder est une layers.LinkType (uint32) — cast direct
		if err := pcapWriter.WriteFileHeader(65535, decoder.(pcapgo.LinkType)); err != nil {
			fmt.Fprintln(os.Stderr, "pcap header error:", err)
		}
	}
```

> **Clarification finale :** `pcapgo.NewWriter.WriteFileHeader(snaplen uint32, linktype layers.LinkType)`. `layers.LinkType` est `uint32`. `decoder` est de type `gopacket.Decoder` (interface). Le `LinkType()` que retourne `h.LinkType()` est `gopacket.Decoder` *et* `layers.LinkType` (car `layers.LinkType` implémente `gopacket.Decoder`). Un simple cast `decoder.(layers.LinkType)` suffit.

- [ ] **Step 5 : Écrire le main.go final propre**

Voici la version finale complète et correcte de `examples/cmd/capture/main.go` :

```go
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
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	iface   := flag.String("i", "", "interface réseau (requis sur Linux)")
	filter  := flag.String("f", "", "filtre: pcap-filter (Linux) ou WinDivert (Windows)")
	count   := flag.Int("n", 0, "nombre de paquets (0 = illimité)")
	outFile := flag.String("w", "", "fichier pcap de sortie (ex: out.pcap)")
	flag.Parse()

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
		lt, ok := decoder.(layers.LinkType)
		if !ok {
			lt = layers.LinkTypeEthernet // fallback
		}
		pcapWriter = pcapgo.NewWriter(f)
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
```

- [ ] **Step 6 : Build check**

```bash
cd /c/Users/m.bachmann/GolandProjects/pkt
GOOS=windows go build ./examples/cmd/capture/
GOOS=linux   go build ./examples/cmd/capture/
```
Résultat attendu : pas d'erreur.

- [ ] **Step 7 : Commit**

```bash
git add examples/cmd/capture/
git commit -m "feat(examples/capture): cross-platform capture + pcap output (-w)"
```

---

### Task 4 : Exemple `modify-payload` (Windows — interception TCP + remplacement de texte)

**Files:**
- Create: `examples/cmd/modify-payload/main.go`

**Comportement :**
- Flags : `-f` filtre WinDivert, `-find` texte à trouver, `-replace` texte de remplacement
- Ouvre WinDivert **sans** `FlagSniff` → intercepte réellement les paquets (le noyau les retient)
- Recv → parse gopacket → si TCP : cherche `-find` dans le payload → remplace
- Recalcule les checksums IP+TCP via `gopacket.SerializeOptions{ComputeChecksums: true}`
- Send (modifié ou original)
- Sur Ctrl+C : Shutdown + Close

- [ ] **Step 1 : Créer `examples/cmd/modify-payload/main.go`**

```go
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

	buf := make([]byte, 65535)
	find    := []byte(*findStr)
	replace := []byte(*replaceStr)
	modified, forwarded := 0, 0

	log.Printf("interception active (filtre: %q, find: %q → replace: %q)", *filterExpr, *findStr, *replaceStr)

	for {
		n, addr, _, err := h.Recv(buf)
		if err != nil {
			break // handle fermé ou shutdown
		}
		data := buf[:n]

		pkt := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
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
```

- [ ] **Step 2 : Build check**

```bash
cd /c/Users/m.bachmann/GolandProjects/pkt
GOOS=windows go build ./examples/cmd/modify-payload/
```
Résultat attendu : pas d'erreur.

- [ ] **Step 3 : Commit**

```bash
git add examples/cmd/modify-payload/
git commit -m "feat(examples/modify-payload): intercept TCP packets and replace payload text (Windows)"
```

---

## Chunk 2 : exemple drop + déplacement capture/ + nettoyage

### Task 5 : Exemple `drop` (Windows — drop de paquets par filtre)

**Files:**
- Create: `examples/cmd/drop/main.go`

**Comportement :**
- Flag unique : `-f` filtre WinDivert définissant ce qui sera droppé
- Ouvre WinDivert sans `FlagSniff` → intercepte les paquets matchant le filtre
- Recv → log → **ne pas Send** → le paquet est droppé par le noyau
- Sur Ctrl+C : Shutdown + Close + stats

- [ ] **Step 1 : Créer `examples/cmd/drop/main.go`**

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
	filterExpr := flag.String("f", "", "filtre WinDivert — paquets matchant ce filtre seront droppés")
	verbose    := flag.Bool("v", false, "affiche les détails de chaque paquet droppé")
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
	go func() { <-ctx.Done(); h.Shutdown() }()

	buf := make([]byte, 65535)
	dropped := 0

	log.Printf("drop actif (filtre: %q) — Ctrl+C pour arrêter", *filterExpr)

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
	log.Printf("terminé — %d paquets droppés", dropped)
}
```

- [ ] **Step 2 : Build check**

```bash
GOOS=windows go build ./examples/cmd/drop/
```
Résultat attendu : pas d'erreur.

- [ ] **Step 3 : Commit**

```bash
git add examples/cmd/drop/
git commit -m "feat(examples/drop): drop packets matching WinDivert filter (Windows)"
```

---

### Task 6 : Supprimer `capture/` et nettoyer

**Files:**
- Delete: `capture/` (entier)
- Modify: `Makefile` (remplacer `capture` par `examples/cmd/capture`)
- Modify: `build.ps1` (idem)

- [ ] **Step 1 : Lire le Makefile actuel**

```bash
cat /c/Users/m.bachmann/GolandProjects/pkt/Makefile
```

- [ ] **Step 2 : Mettre à jour le Makefile**

Remplacer toutes les références à `./capture` ou `pkt/capture` par les trois binaires :

```makefile
EXAMPLES := ./examples/cmd/capture ./examples/cmd/modify-payload ./examples/cmd/drop

build-windows:
	GOOS=windows GOARCH=amd64 go build -o dist/capture-windows-amd64.exe        ./examples/cmd/capture/
	GOOS=windows GOARCH=amd64 go build -o dist/modify-payload-windows-amd64.exe ./examples/cmd/modify-payload/
	GOOS=windows GOARCH=amd64 go build -o dist/drop-windows-amd64.exe           ./examples/cmd/drop/

build-linux:
	GOOS=linux GOARCH=amd64 go build -o dist/capture-linux-amd64 ./examples/cmd/capture/
```

- [ ] **Step 3 : Lire build.ps1 et mettre à jour**

```bash
cat /c/Users/m.bachmann/GolandProjects/pkt/build.ps1
```
Adapter les chemins de la même façon.

- [ ] **Step 4 : Supprimer `capture/`**

```bash
git rm -r capture/
```

- [ ] **Step 5 : Build final tous les exemples**

```bash
cd /c/Users/m.bachmann/GolandProjects/pkt
GOOS=windows go build ./examples/cmd/capture/
GOOS=windows go build ./examples/cmd/modify-payload/
GOOS=windows go build ./examples/cmd/drop/
GOOS=linux   go build ./examples/cmd/capture/
```
Résultat attendu : 0 erreurs.

- [ ] **Step 6 : Commit final**

```bash
git add Makefile build.ps1
git commit -m "chore: remove capture/ module, update Makefile and build.ps1 for examples/"
```

---

## Notes d'implémentation

### WinDivert : interception vs sniff
- `FlagSniff` (0x0001) = sniff only, paquets non bloqués → utilisé dans `capture`
- Sans flag = interception réelle : le noyau retient le paquet jusqu'à `Send()` ou fermeture
- Drop = intercepter (sans FlagSniff) + **ne jamais appeler Send**

### AF_PACKET : limitation Linux
- AF_PACKET ne peut pas bloquer les paquets (pas d'interception noyau)
- `Send()` = injection de nouveaux paquets, pas réinjection
- Pour vrai drop/modify Linux → NFQUEUE (hors scope)

### Checksums gopacket
- `tcp.SetNetworkLayerForChecksum(ip)` est obligatoire avant `SerializeLayers`
- `SerializeOptions{ComputeChecksums: true, FixLengths: true}` recalcule IP+TCP

### pcapgo LinkType
- `layers.LinkType` est `uint32`, implémente `gopacket.Decoder`
- `h.LinkType()` retourne `gopacket.Decoder` qui est en réalité une `layers.LinkType`
- Cast : `decoder.(layers.LinkType)` — safe car WinDivert et afpacket retournent toujours une `layers.LinkType`
