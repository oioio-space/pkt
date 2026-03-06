# pkt workspace — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Go workspace cross-platform packet capture — WinDivert (Windows, pure Go, embedded .sys) + AF_PACKET (Linux, avec filtre BPF kernel-side) — compatible gopacket.

**Architecture:** 4 modules (`pkt/bpf`, `pkt/windivert`, `pkt/afpacket`, `pkt/capture`) dans un Go workspace. WinDivert : embed du driver `.sys`, protocole IOCTL pur Go, filter compiler pigeon (PEG) + bytecode. AF_PACKET : SOCK_RAW + BPF kernel-side via `pkt/bpf`. Pattern `With*` pour les options.

**Tech Stack:** Go 1.22+, `github.com/google/gopacket`, `golang.org/x/sys`, `github.com/mna/pigeon` (build-time), `github.com/packetcap/go-pcap/filter`, `golang.org/x/net/bpf`

**Références :** WinDivert source: https://github.com/basil00/Divert (`windivert.h`, `windivert_device.h`, `winfilter.c`). Constantes Go: https://github.com/imgk/divert-go

---

## Epic 1 — Workspace Setup

### Task 1: go.work + 4 modules init

**Files:**
- Create: `go.work`
- Create: `bpf/go.mod`
- Create: `windivert/go.mod`
- Create: `afpacket/go.mod`
- Create: `capture/go.mod`

**Step 1: Init workspace**

```bash
go work init
mkdir bpf windivert afpacket capture

cd bpf
go mod init pkt/bpf
go get github.com/packetcap/go-pcap/filter
go get golang.org/x/net/bpf
go get golang.org/x/sys/unix

cd ../windivert
go mod init pkt/windivert
go get github.com/google/gopacket
go get golang.org/x/sys/windows

cd ../afpacket
go mod init pkt/afpacket
go get github.com/google/gopacket
go get golang.org/x/sys/unix

cd ../capture
go mod init pkt/capture
go get github.com/google/gopacket
```

**Step 2: Enregistrer les modules dans go.work**

```bash
go work use ./bpf ./windivert ./afpacket ./capture
go work sync
```

Expected: pas d'erreur.

**Step 3: Commit**

```bash
git add go.work bpf/go.mod bpf/go.sum windivert/go.mod windivert/go.sum \
    afpacket/go.mod afpacket/go.sum capture/go.mod capture/go.sum
git commit -m "chore: init go workspace with 4 modules (bpf, windivert, afpacket, capture)"
```

---

## Epic 2 — pkt/bpf (Linux)

> Build tag `//go:build linux` sur tous les fichiers.

### Task 2: bpf — Compile() + Attach()

**Files:**
- Create: `bpf/bpf.go`
- Create: `bpf/bpf_test.go`

**Step 1: Écrire le test**

`bpf/bpf_test.go` :
```go
//go:build linux

package bpf_test

import (
	"testing"
	pkgbpf "pkt/bpf"
)

func TestCompile(t *testing.T) {
	cases := []struct {
		expr    string
		wantErr bool
	}{
		{"true", false},
		{"tcp", false},
		{"tcp port 80", false},
		{"ip and tcp", false},
		{"host 192.168.1.1", false},
		{"", true}, // expression vide
	}
	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			instr, err := pkgbpf.Compile(c.expr)
			if (err != nil) != c.wantErr {
				t.Fatalf("Compile(%q): err=%v wantErr=%v", c.expr, err, c.wantErr)
			}
			if !c.wantErr && len(instr) == 0 {
				t.Errorf("Compile(%q): got 0 instructions", c.expr)
			}
		})
	}
}
```

**Step 2: Run test (FAIL)**
```bash
GOOS=linux go test ./bpf/... 2>&1
```
Expected: FAIL — `bpf` not defined.

**Step 3: Écrire `bpf/bpf.go`**

```go
//go:build linux

// Package bpf compile des expressions pcap-filter en BPF bytecode
// et attache les filtres à des sockets AF_PACKET via SO_ATTACH_FILTER.
package bpf

import (
	"fmt"
	"unsafe"

	goBPF "golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/packetcap/go-pcap/filter"
)

// Compile parse une expression pcap-filter style et retourne les instructions BPF.
// Exemples : "tcp port 80", "ip and tcp", "host 192.168.1.1"
func Compile(expr string) ([]goBPF.Instruction, error) {
	if expr == "" {
		return nil, fmt.Errorf("empty filter expression")
	}
	e := filter.NewExpression(expr)
	f := e.Compile()
	instr, err := f.Compile()
	if err != nil {
		return nil, fmt.Errorf("compile BPF %q: %w", expr, err)
	}
	return instr, nil
}

// Attach attache un filtre BPF à un socket (SO_ATTACH_FILTER).
func Attach(fd int, instructions []goBPF.Instruction) error {
	raw, err := goBPF.Assemble(instructions)
	if err != nil {
		return fmt.Errorf("assemble BPF: %w", err)
	}
	prog := unix.SockFprog{
		Len:    uint16(len(raw)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&raw[0])),
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
}

// Detach retire le filtre BPF d'un socket (SO_DETACH_FILTER).
func Detach(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0)
}
```

**Step 4: Run test (PASS)**
```bash
GOOS=linux go test ./bpf/... -v
```

**Step 5: Commit**
```bash
git add bpf/bpf.go bpf/bpf_test.go
git commit -m "feat(bpf): BPF filter compile + attach via SO_ATTACH_FILTER"
```

---

## Epic 3 — pkt/afpacket (Linux)

> Build tag `//go:build linux` sur tous les fichiers.

### Task 3: afpacket — options + API publique

**Files:**
- Create: `afpacket/afpacket.go`
- Create: `afpacket/afpacket_test.go`

**Step 1: Écrire le test**

```go
//go:build linux

package afpacket_test

import (
	"testing"
	"pkt/afpacket"
)

func TestOptions(t *testing.T) {
	opts := afpacket.DefaultOptions()
	afpacket.WithPromiscuous(true)(&opts)
	afpacket.WithSnapLen(1500)(&opts)
	afpacket.WithFilter("tcp port 80")(&opts)
	if !opts.Promiscuous  { t.Error("promiscuous not set") }
	if opts.SnapLen != 1500 { t.Error("snaplen not set") }
	if opts.Filter != "tcp port 80" { t.Error("filter not set") }
}
```

**Step 2: Run test (FAIL)**
```bash
GOOS=linux go test ./afpacket/... 2>&1
```

**Step 3: Écrire `afpacket/afpacket.go`**

```go
//go:build linux

package afpacket

import "github.com/google/gopacket"

// Option configure un Handle.
type Option func(*Options)

// Options contient la configuration d'un Handle.
type Options struct {
	SnapLen     int
	Promiscuous bool
	Filter      string // expression pcap-filter, vide = pas de filtre kernel
}

// DefaultOptions retourne la configuration par défaut.
func DefaultOptions() Options {
	return Options{SnapLen: 65535, Promiscuous: true}
}

// WithSnapLen définit la taille maximale des paquets capturés.
func WithSnapLen(n int) Option { return func(o *Options) { o.SnapLen = n } }

// WithPromiscuous active/désactive le mode promiscuous.
func WithPromiscuous(b bool) Option { return func(o *Options) { o.Promiscuous = b } }

// WithFilter attache un filtre BPF kernel-side (ex: "tcp port 80").
// Requiert pkt/bpf. Vide = pas de filtre (tout capturer).
func WithFilter(expr string) Option { return func(o *Options) { o.Filter = expr } }

// Handle représente un socket AF_PACKET ouvert.
type Handle struct {
	fd   int
	opts Options
}

// Open ouvre un socket AF_PACKET sur l'interface donnée.
func Open(iface string, opts ...Option) (*Handle, error) {
	o := DefaultOptions()
	for _, opt := range opts { opt(&o) }
	return open(iface, o)
}

// Close ferme le socket.
func (h *Handle) Close() error { return closeHandle(h) }

// ReadPacketData implémente gopacket.PacketDataSource.
func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return readPacket(h)
}

// LinkType retourne le decoder gopacket.
func (h *Handle) LinkType() gopacket.Decoder { return linkType() }
```

**Step 4: Run test (PASS)**
```bash
GOOS=linux go test ./afpacket/... -run TestOptions -v
```

**Step 5: Commit**
```bash
git add afpacket/afpacket.go afpacket/afpacket_test.go
git commit -m "feat(afpacket): public API + options (WithFilter, WithPromiscuous, WithSnapLen)"
```

---

### Task 4: afpacket — socket + bind + promiscuous + recv

**Files:**
- Create: `afpacket/socket.go`
- Create: `afpacket/promiscuous.go`
- Create: `afpacket/source.go`

**Step 1: `afpacket/socket.go`**

```go
//go:build linux

package afpacket

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
	pkgbpf "pkt/bpf"
)

func htons(i uint16) uint16 { return (i << 8) | (i >> 8) }

func open(iface string, o Options) (*Handle, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	sll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, &sll); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}

	h := &Handle{fd: fd, opts: o}

	if o.Promiscuous {
		if err := setPromiscuous(fd, ifi.Index, true); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}

	if o.Filter != "" {
		instr, err := pkgbpf.Compile(o.Filter)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("bpf filter: %w", err)
		}
		if err := pkgbpf.Attach(fd, instr); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("attach bpf: %w", err)
		}
	}

	return h, nil
}

func closeHandle(h *Handle) error { return unix.Close(h.fd) }
```

**Step 2: `afpacket/promiscuous.go`**

```go
//go:build linux

package afpacket

import "golang.org/x/sys/unix"

func setPromiscuous(fd, ifIndex int, enable bool) error {
	mr := unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_PROMISC,
	}
	opt := unix.PACKET_ADD_MEMBERSHIP
	if !enable {
		opt = unix.PACKET_DROP_MEMBERSHIP
	}
	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, opt, &mr)
}
```

**Step 3: `afpacket/source.go`**

```go
//go:build linux

package afpacket

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func readPacket(h *Handle) ([]byte, gopacket.CaptureInfo, error) {
	buf := make([]byte, h.opts.SnapLen)
	n, _, err := unix.Recvfrom(h.fd, buf, 0)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: n,
		Length:        n,
	}
	return buf[:n], ci, nil
}

func linkType() gopacket.Decoder { return layers.LayerTypeEthernet }
```

**Step 4: Écrire le test d'intégration (skip si pas root)**

`afpacket/socket_test.go` :
```go
//go:build linux

package afpacket

import (
	"os"
	"testing"
)

func TestIfaceOpen(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	h, err := open("lo", DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
}
```

**Step 5: Build check**
```bash
GOOS=linux go build ./afpacket/...
```
Expected: compile sans erreur.

**Step 6: Commit**
```bash
git add afpacket/socket.go afpacket/promiscuous.go afpacket/source.go afpacket/socket_test.go
git commit -m "feat(afpacket): socket AF_PACKET + bind + promiscuous + BPF attach + recv"
```

---

## Epic 4 — pkt/windivert (Windows)

> Build tag `//go:build windows` sur tous les fichiers.
> **Avant de commencer :** lire `windivert.h`, `windivert_device.h`, `winfilter.c` dans le source WinDivert 2.x et `addr.go` dans `imgk/divert-go` pour les valeurs exactes des IOCTL codes et structures.

### Task 5: windivert — constantes + WINDIVERT_ADDRESS

**Files:**
- Create: `windivert/const.go`
- Create: `windivert/address.go`

**Step 1: `windivert/const.go`**

```go
//go:build windows

package windivert

// Layer définit le niveau de capture WinDivert.
type Layer uint32

const (
	LayerNetwork        Layer = 0
	LayerNetworkForward Layer = 1
	LayerFlow           Layer = 2
	LayerSocket         Layer = 3
	LayerReflect        Layer = 4
)

// Flags pour Open().
const (
	FlagSniff     uint64 = 1 << 0
	FlagDrop      uint64 = 1 << 1
	FlagRecvOnly  uint64 = 1 << 2
	FlagSendOnly  uint64 = 1 << 3
	FlagNoInstall uint64 = 1 << 4
	FlagFragments uint64 = 1 << 5
)

// IOCTL function codes (CTL_CODE function parameter).
// Source : windivert_device.h — vérifier les valeurs exactes.
// imgk/divert-go IoCtl* constants comme référence.
const (
	ioctlInitialize = uint32(0x921) // vérifier avec CTL_CODE macro
	ioctlStartup    = uint32(0x922)
	ioctlShutdown   = uint32(0x927)
	ioctlSetParam   = uint32(0x925)
	ioctlGetParam   = uint32(0x926)
)

// Device path WinDivert 2.x.
const devicePath = `\\.\WinDivert`
```

**⚠️ Note :** Les valeurs `ioctlInitialize` etc. sont les function codes, pas les IOCTL codes complets. Le code complet est `CTL_CODE(FILE_DEVICE_NETWORK, func, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)`. Calculer avec la macro ou vérifier dans `imgk/divert-go`.

**Step 2: `windivert/address.go`**

```go
//go:build windows

package windivert

// Address contient les métadonnées d'un paquet WinDivert.
// Correspond à WINDIVERT_ADDRESS dans windivert.h (v2.x).
// ⚠️ Vérifier le layout exact (taille, offset des champs) dans windivert.h.
type Address struct {
	Timestamp int64 // LARGE_INTEGER — timestamp du paquet
	// Bitfield encodé dans un uint32 — layout à vérifier
	// bits: Layer(8), Event(8), Sniff(1), Outbound(1), Loopback(1),
	//       Impostor(1), IPv6(1), IPChecksum(1), TCPChecksum(1), UDPChecksum(1), Reserved(8)
	Flags uint32
	// Union selon Layer — pour LayerNetwork :
	Network struct {
		IfIdx    uint32 // interface index
		SubIfIdx uint32 // sub-interface index
	}
	Reserved [48]byte // taille totale WINDIVERT_ADDRESS = 80 bytes — vérifier
}

// IsOutbound retourne true si le paquet est sortant.
// Bit position à vérifier dans windivert.h WINDIVERT_ADDRESS.Outbound.
func (a *Address) IsOutbound() bool { return a.Flags&(1<<18) != 0 }

// IsLoopback retourne true si le paquet est loopback.
func (a *Address) IsLoopback() bool { return a.Flags&(1<<19) != 0 }
```

**Step 3: Commit**
```bash
git add windivert/const.go windivert/address.go
git commit -m "feat(windivert): constants + WINDIVERT_ADDRESS structure"
```

---

### Task 6: windivert/filter — grammaire pigeon

**Files:**
- Create: `windivert/filter/grammar.peg`
- Create: `windivert/filter/doc.go`
- Generate: `windivert/filter/grammar.go` (commiter le fichier généré)

**Step 1: Installer pigeon (outil build-time)**

```bash
go install github.com/mna/pigeon@latest
```

**Step 2: Écrire `windivert/filter/doc.go`**

```go
//go:build windows

// Package filter compile des filtres WinDivert 2.x en bytecode driver.
// La grammaire PEG est dans grammar.peg, grammar.go est généré (ne pas éditer).
//
//go:generate pigeon -o grammar.go grammar.peg
package filter
```

**Step 3: Écrire `windivert/filter/grammar.peg`**

La grammaire WinDivert 2.x complète. Grammaire à écrire dans `grammar.peg` :

```peg
{
// Package filter
package filter

// Node est le type retourné par le parser.
type Node interface{ nodeKind() string }

type BoolNode   struct{ Value bool }
type FieldNode  struct{ Parts []string }
type CmpNode    struct{ Field []string; Op string; Value string; VTok string }
type BinaryNode struct{ Op string; Left, Right Node }
type UnaryNode  struct{ Child Node }

func (n *BoolNode) nodeKind() string   { return "bool" }
func (n *FieldNode) nodeKind() string  { return "field" }
func (n *CmpNode) nodeKind() string    { return "cmp" }
func (n *BinaryNode) nodeKind() string { return "binary" }
func (n *UnaryNode) nodeKind() string  { return "unary" }

func toStr(v interface{}) string {
    b, _ := v.([]byte)
    return string(b)
}
func toNode(v interface{}) Node {
    n, _ := v.(Node)
    return n
}
}

// Point d'entrée
Input <- _ e:OrExpr _ EOF { return e, nil }

// Précédence : OR < AND < NOT < primary
OrExpr  <- l:AndExpr rest:( _ ("or" / "||") _ r:AndExpr { return r, nil } )* {
    node := l.(Node)
    for _, r := range rest.([]interface{}) {
        node = &BinaryNode{"or", node, r.(Node)}
    }
    return node, nil
}

AndExpr <- l:NotExpr rest:( _ ("and" / "&&") _ r:NotExpr { return r, nil } )* {
    node := l.(Node)
    for _, r := range rest.([]interface{}) {
        node = &BinaryNode{"and", node, r.(Node)}
    }
    return node, nil
}

NotExpr <- ("!" / "not" _) e:NotExpr { return &UnaryNode{e.(Node)}, nil }
         / Primary

Primary <- "(" _ e:OrExpr _ ")" { return e, nil }
         / "true"               { return &BoolNode{true}, nil }
         / "false"              { return &BoolNode{false}, nil }
         / FieldCmp

FieldCmp <- f:Field _ op:Op _ v:Value {
    fc := f.(*FieldNode)
    val, tok := v.([]interface{})[0].(string), v.([]interface{})[1].(string)
    return &CmpNode{fc.Parts, op.(string), val, tok}, nil
}
         / f:Field { return f, nil }

Field <- head:Ident tail:( "." i:Ident { return i, nil } )* {
    parts := []string{head.(string)}
    for _, t := range tail.([]interface{}) {
        parts = append(parts, t.(string))
    }
    return &FieldNode{parts}, nil
}

Op <- ">=" { return ">=", nil }
    / "<=" { return "<=", nil }
    / "!=" { return "!=", nil }
    / "==" { return "==", nil }
    / "<"  { return "<", nil }
    / ">"  { return ">", nil }

Value <- ip6:IPv6Addr { return []interface{}{ip6.(string), "ip6addr"}, nil }
       / ip4:IPv4Addr { return []interface{}{ip4.(string), "ipaddr"}, nil }
       / hex:HexNum   { return []interface{}{hex.(string), "number"}, nil }
       / dec:DecNum   { return []interface{}{dec.(string), "number"}, nil }

IPv4Addr <- d:DecNum "." d2:DecNum "." d3:DecNum "." d4:DecNum {
    return d.(string) + "." + d2.(string) + "." + d3.(string) + "." + d4.(string), nil
}

IPv6Addr <- h:[0-9a-fA-F]+ rest:( ":" [0-9a-fA-F]* )+ {
    s := string(h.([]byte))
    for _, r := range rest.([]interface{}) {
        s += ":" + string(r.([]interface{})[1].([]byte))
    }
    return s, nil
}

HexNum <- "0x" h:[0-9a-fA-F]+ { return "0x" + string(h.([]byte)), nil }

DecNum <- d:[0-9]+ { return string(d.([]byte)), nil }

Ident  <- h:[a-zA-Z_] t:[a-zA-Z0-9_]* {
    return string(h.([]byte)) + string(t.([]byte)), nil  // simplifié
}

_ "whitespace" <- [ \t\n\r]*
EOF <- !.
```

**Step 4: Générer le parser**

```bash
cd windivert
go generate ./filter/...
```

Expected: `windivert/filter/grammar.go` généré.

**Step 5: Vérifier la compilation**

```bash
GOOS=windows go build ./filter/...
```

**Step 6: Écrire le test du parser**

`windivert/filter/grammar_test.go` :
```go
//go:build windows

package filter_test

import (
	"testing"
	"pkt/windivert/filter"
)

func TestParse(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
	}{
		{"true", false},
		{"false", false},
		{"ip", false},
		{"tcp", false},
		{"tcp.DstPort == 80", false},
		{"ip and tcp", false},
		{"ip or udp", false},
		{"!tcp", false},
		{"(ip and tcp) or udp", false},
		{"tcp.DstPort == 443 and ip.SrcAddr == 192.168.1.1", false},
		{"ipv6.DstAddr == ::1", false},
		{"==", true},
		{"ip and", true},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			_, err := filter.Parse("input", []byte(c.input))
			if (err != nil) != c.wantErr {
				t.Fatalf("Parse(%q) err=%v wantErr=%v", c.input, err, c.wantErr)
			}
		})
	}
}
```

**Step 7: Run test (PASS)**
```bash
GOOS=windows go test ./windivert/filter/... -run TestParse -v
```

**Step 8: Commit**
```bash
git add windivert/filter/doc.go windivert/filter/grammar.peg windivert/filter/grammar.go windivert/filter/grammar_test.go
git commit -m "feat(windivert/filter): pigeon PEG grammar + generated parser"
```

---

### Task 7: windivert/filter — table des champs + compiler bytecode

**Files:**
- Create: `windivert/filter/fields.go`
- Create: `windivert/filter/compiler.go`
- Create: `windivert/filter/compiler_test.go`

**Step 1: `windivert/filter/fields.go`**

```go
//go:build windows

package filter

import (
	"fmt"
	"strings"
)

// FieldKind décrit le type d'un champ WinDivert.
type FieldKind uint8

const (
	KindBool   FieldKind = iota
	KindUint8
	KindUint16
	KindUint32
	KindUint64
	KindIPv4
	KindIPv6
)

// FieldDef définit un champ WinDivert connu.
type FieldDef struct {
	ID   uint32    // identifiant dans le bytecode (vérifier dans winfilter.c)
	Kind FieldKind
}

// fieldTable : IDs à vérifier contre WINDIVERT_FILTER_FIELD_* dans winfilter.c.
var fieldTable = map[string]FieldDef{
	"Zero": {0, KindUint8}, "Event": {1, KindUint8},
	"Random8": {2, KindUint8}, "Random16": {3, KindUint16},
	"Random32": {4, KindUint32}, "Timestamp": {5, KindUint64},
	"Length": {6, KindUint16},
	// IPv4
	"ip": {10, KindBool},
	"ip.HdrLength": {11, KindUint8}, "ip.TOS": {12, KindUint8},
	"ip.Length": {13, KindUint16}, "ip.Id": {14, KindUint16},
	"ip.MF": {15, KindBool}, "ip.FragOff": {16, KindUint16},
	"ip.TTL": {17, KindUint8}, "ip.Protocol": {18, KindUint8},
	"ip.Checksum": {19, KindUint16},
	"ip.SrcAddr": {20, KindIPv4}, "ip.DstAddr": {21, KindIPv4},
	// IPv6
	"ipv6": {30, KindBool},
	"ipv6.TrafficClass": {31, KindUint8}, "ipv6.FlowLabel": {32, KindUint32},
	"ipv6.Length": {33, KindUint16}, "ipv6.NextHdr": {34, KindUint8},
	"ipv6.HopLimit": {35, KindUint8},
	"ipv6.SrcAddr": {36, KindIPv6}, "ipv6.DstAddr": {37, KindIPv6},
	// TCP
	"tcp": {40, KindBool},
	"tcp.SrcPort": {41, KindUint16}, "tcp.DstPort": {42, KindUint16},
	"tcp.SeqNum": {43, KindUint32}, "tcp.AckNum": {44, KindUint32},
	"tcp.HdrLength": {45, KindUint8},
	"tcp.Ns": {46, KindBool}, "tcp.Cwr": {47, KindBool},
	"tcp.Ece": {48, KindBool}, "tcp.Urg": {49, KindBool},
	"tcp.Ack": {50, KindBool}, "tcp.Psh": {51, KindBool},
	"tcp.Rst": {52, KindBool}, "tcp.Syn": {53, KindBool},
	"tcp.Fin": {54, KindBool}, "tcp.Window": {55, KindUint16},
	"tcp.Checksum": {56, KindUint16}, "tcp.UrgPtr": {57, KindUint16},
	"tcp.PayloadLength": {58, KindUint16},
	// UDP
	"udp": {60, KindBool},
	"udp.SrcPort": {61, KindUint16}, "udp.DstPort": {62, KindUint16},
	"udp.Length": {63, KindUint16}, "udp.Checksum": {64, KindUint16},
	"udp.PayloadLength": {65, KindUint16},
	// ICMP / ICMPv6
	"icmp": {70, KindBool},
	"icmp.Type": {71, KindUint8}, "icmp.Code": {72, KindUint8},
	"icmp.Checksum": {73, KindUint16}, "icmp.Body": {74, KindUint32},
	"icmpv6": {80, KindBool},
	"icmpv6.Type": {81, KindUint8}, "icmpv6.Code": {82, KindUint8},
	"icmpv6.Checksum": {83, KindUint16}, "icmpv6.Body": {84, KindUint32},
}

// LookupField recherche la définition d'un champ par ses parts.
func LookupField(parts []string) (FieldDef, error) {
	key := strings.Join(parts, ".")
	def, ok := fieldTable[key]
	if !ok {
		return FieldDef{}, fmt.Errorf("unknown WinDivert field: %q", key)
	}
	return def, nil
}
```

**Step 2: `windivert/filter/compiler.go`**

```go
//go:build windows

package filter

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unsafe"
)

// FilterObject est un objet du bytecode WinDivert.
// Layout à vérifier dans windivert_device.h WINDIVERT_FILTER_OBJECT.
type FilterObject struct {
	Val     [4]uint32 // valeur comparée (128 bits)
	Field   uint32    // ID du champ (24 bits utiles)
	Test    uint8     // 0=EQ,1=NEQ,2=LT,3=LE,4=GT,5=GE,6=TRUE,7=FALSE
	Neg     uint8     // 1=nié
	Success uint16    // saut si vrai (index relatif ou absolu — vérifier spec)
	Failure uint16    // saut si faux
}

const (
	testEQ    uint8 = 0
	testNEQ   uint8 = 1
	testLT    uint8 = 2
	testLE    uint8 = 3
	testGT    uint8 = 4
	testGE    uint8 = 5
	testTrue  uint8 = 6
	testFalse uint8 = 7
)

// Compile compile un filtre WinDivert 2.x en bytecode.
func Compile(filterStr string) ([]FilterObject, error) {
	ast, err := Parse("filter", []byte(filterStr))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	c := &compiler{}
	if err := c.emit(ast.(Node)); err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	c.patchJumps()
	return c.prog, nil
}

type compiler struct {
	prog []FilterObject
}

func (c *compiler) emit(n Node) error {
	switch node := n.(type) {
	case *BoolNode:
		test := testTrue
		if !node.Value {
			test = testFalse
		}
		c.prog = append(c.prog, FilterObject{Test: test})
	case *FieldNode:
		def, err := LookupField(node.Parts)
		if err != nil {
			return err
		}
		c.prog = append(c.prog, FilterObject{Field: def.ID, Test: testTrue})
	case *CmpNode:
		return c.emitCmp(node)
	case *UnaryNode:
		start := len(c.prog)
		if err := c.emit(node.Child); err != nil {
			return err
		}
		// Inverser Success/Failure de tous les objets émis
		for i := start; i < len(c.prog); i++ {
			c.prog[i].Success, c.prog[i].Failure = c.prog[i].Failure, c.prog[i].Success
			c.prog[i].Neg ^= 1
		}
	case *BinaryNode:
		return c.emitBinary(node)
	default:
		return fmt.Errorf("unknown node type %T", n)
	}
	return nil
}

func (c *compiler) emitCmp(n *CmpNode) error {
	def, err := LookupField(n.Field)
	if err != nil {
		return err
	}
	val, err := parseValue(n.Value, n.VTok, def.Kind)
	if err != nil {
		return err
	}
	c.prog = append(c.prog, FilterObject{
		Field: def.ID,
		Val:   val,
		Test:  opToTest(n.Op),
	})
	return nil
}

func (c *compiler) emitBinary(n *BinaryNode) error {
	// AND : left FAIL → skip right (FAIL global); left SUCCESS → eval right
	// OR  : left SUCCESS → skip right (SUCCESS global); left FAIL → eval right
	// Implémentation : émettre left, noter position, émettre right, patcher jumps.
	// ⚠️ Le format exact des jumps (relatifs vs absolus) doit être vérifié dans
	// winfilter.c (fonction WinDivertFilterCompile).
	leftStart := len(c.prog)
	if err := c.emit(n.Left); err != nil {
		return err
	}
	leftEnd := len(c.prog)
	if err := c.emit(n.Right); err != nil {
		return err
	}
	rightEnd := len(c.prog)

	// Patch simplifié — à affiner après étude de winfilter.c
	if n.Op == "and" {
		// left failure → jump après right (FAIL total)
		for i := leftStart; i < leftEnd; i++ {
			c.prog[i].Failure = uint16(rightEnd)
		}
	} else { // or
		// left success → jump après right (SUCCESS total)
		for i := leftStart; i < leftEnd; i++ {
			c.prog[i].Success = uint16(rightEnd)
		}
	}
	return nil
}

// patchJumps finalise les jumps 0 (non patchés) → index final (ACCEPT/REJECT).
// ⚠️ La sémantique exacte (WINDIVERT_FILTER_RESULT_ACCEPT/REJECT) à vérifier.
func (c *compiler) patchJumps() {
	last := uint16(len(c.prog))
	for i := range c.prog {
		if c.prog[i].Success == 0 {
			c.prog[i].Success = last // ACCEPT
		}
		if c.prog[i].Failure == 0 {
			c.prog[i].Failure = last + 1 // REJECT
		}
	}
}

func opToTest(op string) uint8 {
	switch op {
	case "==":
		return testEQ
	case "!=":
		return testNEQ
	case "<":
		return testLT
	case "<=":
		return testLE
	case ">":
		return testGT
	case ">=":
		return testGE
	}
	return testTrue
}

func parseValue(raw, tok string, kind FieldKind) ([4]uint32, error) {
	var val [4]uint32
	switch tok {
	case "number":
		raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
		n, err := strconv.ParseUint(raw, 0, 64)
		if err != nil {
			return val, fmt.Errorf("invalid number %q: %w", raw, err)
		}
		val[0] = uint32(n)
		val[1] = uint32(n >> 32)
	case "ipaddr":
		ip := net.ParseIP(raw).To4()
		if ip == nil {
			return val, fmt.Errorf("invalid IPv4 %q", raw)
		}
		val[0] = binary.BigEndian.Uint32(ip)
	case "ip6addr":
		ip := net.ParseIP(raw).To16()
		if ip == nil {
			return val, fmt.Errorf("invalid IPv6 %q", raw)
		}
		val[0] = binary.BigEndian.Uint32(ip[0:4])
		val[1] = binary.BigEndian.Uint32(ip[4:8])
		val[2] = binary.BigEndian.Uint32(ip[8:12])
		val[3] = binary.BigEndian.Uint32(ip[12:16])
	}
	return val, nil
}

// Bytes sérialise le programme en bytes pour le passer à DeviceIoControl.
func Bytes(prog []FilterObject) []byte {
	size := len(prog) * int(unsafe.Sizeof(FilterObject{}))
	buf := make([]byte, size)
	for i, obj := range prog {
		off := i * int(unsafe.Sizeof(obj))
		copy(buf[off:], (*[unsafe.Sizeof(FilterObject{})]byte)(unsafe.Pointer(&obj))[:])
	}
	return buf
}
```

**Step 3: Écrire le test du compiler**

`windivert/filter/compiler_test.go` :
```go
//go:build windows

package filter_test

import (
	"testing"
	"pkt/windivert/filter"
)

func TestCompile(t *testing.T) {
	cases := []struct {
		filter  string
		wantErr bool
		minLen  int
	}{
		{"true", false, 1},
		{"false", false, 1},
		{"ip", false, 1},
		{"tcp.DstPort == 80", false, 1},
		{"ip and tcp", false, 2},
		{"ip or udp", false, 2},
		{"!tcp", false, 1},
		{"unknown.Field == 1", true, 0},
	}
	for _, c := range cases {
		t.Run(c.filter, func(t *testing.T) {
			prog, err := filter.Compile(c.filter)
			if (err != nil) != c.wantErr {
				t.Fatalf("Compile(%q): err=%v wantErr=%v", c.filter, err, c.wantErr)
			}
			if !c.wantErr && len(prog) < c.minLen {
				t.Errorf("got %d objects, want >= %d", len(prog), c.minLen)
			}
		})
	}
}
```

**Step 4: Run tests (PASS)**
```bash
GOOS=windows go test ./windivert/filter/... -v
```

**Step 5: Commit**
```bash
git add windivert/filter/fields.go windivert/filter/compiler.go windivert/filter/compiler_test.go
git commit -m "feat(windivert/filter): field table + bytecode compiler"
```

---

### Task 8: windivert/driver — SCM installer + embed .sys

**Files:**
- Create: `windivert/driver/installer.go`
- Create: `windivert/assets/embed.go`
- Add: `windivert/assets/WinDivert64.sys` (binaire, téléchargé)

**Step 1: Télécharger WinDivert64.sys**

Depuis https://github.com/basil00/Divert/releases (latest v2.x) :
```bash
# Extraire WinDivert64.sys de l'archive release
cp /path/to/release/x64/WinDivert64.sys windivert/assets/
```

**Step 2: `windivert/assets/embed.go`**

```go
//go:build windows

package assets

import _ "embed"

// Sys64 contient le binaire WinDivert64.sys.
//
//go:embed WinDivert64.sys
var Sys64 []byte
```

**Step 3: `windivert/driver/installer.go`**

```go
//go:build windows

package driver

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WinDivert"

// Install extrait le .sys et installe le driver WinDivert via SCM.
// Idempotent — retourne nil si déjà en cours d'exécution.
func Install(sysData []byte) error {
	sysPath, err := extractSys(sysData)
	if err != nil {
		return fmt.Errorf("extract sys: %w", err)
	}
	return installService(sysPath)
}

// Uninstall arrête et supprime le service WinDivert.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // pas installé
	}
	defer s.Close()
	_ = s.Control(windows.SERVICE_CONTROL_STOP)
	return s.Delete()
}

// OpenDevice ouvre le device WinDivert et retourne un handle Windows.
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

func extractSys(data []byte) (string, error) {
	dir, err := os.MkdirTemp("", "windivert-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "WinDivert64.sys")
	return path, os.WriteFile(path, data, 0600)
}

func installService(sysPath string) error {
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

	s, err = m.CreateService(serviceName, sysPath, mgr.Config{
		ServiceType:  windows.SERVICE_KERNEL_DRIVER,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "WinDivert Network Driver",
	})
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer s.Close()
	return s.Start()
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
```

**Step 4: Build check**
```bash
GOOS=windows go build ./windivert/...
```

**Step 5: Commit**
```bash
git add windivert/assets/embed.go windivert/assets/WinDivert64.sys windivert/driver/installer.go
git commit -m "feat(windivert/driver): embed WinDivert64.sys + SCM installer"
```

---

### Task 9: windivert — Handle + overlapped I/O + API publique

**Files:**
- Create: `windivert/handle.go`
- Create: `windivert/windivert.go`
- Create: `windivert/source.go`

**Step 1: `windivert/handle.go`**

```go
//go:build windows

package windivert

import (
	"fmt"

	"golang.org/x/sys/windows"
	"pkt/windivert/filter"
)

// Handle représente un handle WinDivert ouvert.
type Handle struct {
	win   windows.Handle
	layer Layer
	opts  options
}

// Close ferme le handle WinDivert.
func (h *Handle) Close() error { return windows.CloseHandle(h.win) }

// Recv reçoit un paquet. Bloque jusqu'à réception.
func (h *Handle) Recv(buf []byte) (int, *Address, error) {
	var recvLen uint32
	addr := new(Address)
	ov := new(windows.Overlapped)
	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("CreateEvent: %w", err)
	}
	defer windows.CloseHandle(ev)
	ov.HEvent = ev

	err = windows.ReadFile(h.win, buf, &recvLen, ov)
	if err == windows.ERROR_IO_PENDING {
		if _, err = windows.WaitForSingleObject(ev, windows.INFINITE); err != nil {
			return 0, nil, err
		}
		err = windows.GetOverlappedResult(h.win, ov, &recvLen, false)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("Recv: %w", err)
	}
	return int(recvLen), addr, nil
}

// Send injecte un paquet dans le réseau.
func (h *Handle) Send(data []byte, addr *Address) error {
	var sent uint32
	return windows.WriteFile(h.win, data, &sent, nil)
}

// ioctl envoie un IOCTL au driver WinDivert.
func (h *Handle) ioctl(code, in, out []byte) error {
	var returned uint32
	var inPtr, outPtr *byte
	var inLen, outLen uint32
	if len(in) > 0 {
		inPtr = &in[0]
		inLen = uint32(len(in))
	}
	if len(out) > 0 {
		outPtr = &out[0]
		outLen = uint32(len(out))
	}
	// code est le IOCTL code complet (CTL_CODE) — voir const.go
	ioctlCode := uint32(0) // TODO: calculer depuis ioctlInitialize + CTL_CODE
	return windows.DeviceIoControl(h.win, ioctlCode, inPtr, inLen, outPtr, outLen, &returned, nil)
}

// initialize envoie le filtre compilé et démarre la capture.
func (h *Handle) initialize(prog []filter.FilterObject, priority int16, flags uint64) error {
	buf := filter.Bytes(prog)
	// IOCTL_INITIALIZE — structure à vérifier dans windivert_device.h
	// Inclut layer, priority, flags + bytecode du filtre
	if err := windows.DeviceIoControl(
		h.win, ioctlInitialize, // TODO: code IOCTL complet
		&buf[0], uint32(len(buf)),
		nil, 0, nil, nil,
	); err != nil {
		return fmt.Errorf("IOCTL_INITIALIZE: %w", err)
	}
	return windows.DeviceIoControl(
		h.win, ioctlStartup,
		nil, 0, nil, 0, nil, nil,
	)
}
```

**Step 2: `windivert/windivert.go`**

```go
//go:build windows

package windivert

import (
	"fmt"

	"pkt/windivert/assets"
	"pkt/windivert/driver"
	"pkt/windivert/filter"
)

type options struct {
	SnapLen  int
	Priority int16
	Flags    uint64
}

func defaultOptions() options { return options{SnapLen: 65535} }

// Option configure un Handle.
type Option func(*options)

// WithSnapLen définit la taille max des paquets.
func WithSnapLen(n int) Option { return func(o *options) { o.SnapLen = n } }

// WithPriority définit la priorité WinDivert (-30000..30000).
func WithPriority(p int16) Option { return func(o *options) { o.Priority = p } }

// WithFlags définit les flags WinDivert (FlagSniff, FlagDrop...).
func WithFlags(f uint64) Option { return func(o *options) { o.Flags = f } }

// Open installe le driver, compile le filtre et ouvre un Handle WinDivert.
// Requiert des droits administrateur.
func Open(filterStr string, layer Layer, opts ...Option) (*Handle, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	if err := driver.Install(assets.Sys64); err != nil {
		return nil, fmt.Errorf("install driver: %w", err)
	}
	prog, err := filter.Compile(filterStr)
	if err != nil {
		return nil, fmt.Errorf("compile filter: %w", err)
	}
	win, err := driver.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("open device: %w", err)
	}
	h := &Handle{win: win, layer: layer, opts: o}
	if err := h.initialize(prog, o.Priority, o.Flags); err != nil {
		h.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	return h, nil
}
```

**Step 3: `windivert/source.go`**

```go
//go:build windows

package windivert

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ReadPacketData implémente gopacket.PacketDataSource.
func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	buf := make([]byte, h.opts.SnapLen)
	n, _, err := h.Recv(buf)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	return buf[:n], gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: n,
		Length:        n,
	}, nil
}

// LinkType retourne le decoder gopacket selon le layer.
func (h *Handle) LinkType() gopacket.Decoder {
	if h.layer == LayerNetwork || h.layer == LayerNetworkForward {
		return layers.LayerTypeIPv4
	}
	return layers.LayerTypeEthernet
}
```

**Step 4: Build check**
```bash
GOOS=windows go build ./windivert/...
```

**Step 5: Commit**
```bash
git add windivert/handle.go windivert/windivert.go windivert/source.go
git commit -m "feat(windivert): Handle overlapped I/O + Open API + gopacket source"
```

---

## Epic 5 — pkt/capture (cross-platform)

### Task 10: capture — main + sources par OS

**Files:**
- Create: `capture/source_linux.go`
- Create: `capture/source_windows.go`
- Create: `capture/main.go`

**Step 1: Mettre à jour `capture/go.mod`**

Ajouter les dépendances locales (go.work gère les replace directives automatiquement) :
```bash
cd capture
go get pkt/windivert
go get pkt/afpacket
```

**Step 2: `capture/source_linux.go`**

```go
//go:build linux

package main

import (
	"github.com/google/gopacket"
	"pkt/afpacket"
)

func newSource(iface, filter string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	opts := []afpacket.Option{afpacket.WithPromiscuous(true)}
	if filter != "" {
		opts = append(opts, afpacket.WithFilter(filter))
	}
	h, err := afpacket.Open(iface, opts...)
	if err != nil {
		return nil, nil, err
	}
	return h, h.LinkType(), nil
}
```

**Step 3: `capture/source_windows.go`**

```go
//go:build windows

package main

import (
	"github.com/google/gopacket"
	"pkt/windivert"
)

func newSource(_, filter string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	if filter == "" {
		filter = "true"
	}
	h, err := windivert.Open(filter, windivert.LayerNetwork)
	if err != nil {
		return nil, nil, err
	}
	return h, h.LinkType(), nil
}
```

**Step 4: `capture/main.go`**

```go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
)

func main() {
	iface  := flag.String("i", "", "interface réseau (requis sur Linux)")
	filter := flag.String("f", "", "filtre: pcap-filter sur Linux, WinDivert sur Windows")
	count  := flag.Int("n", 0, "nb paquets à capturer (0=infini)")
	flag.Parse()

	src, decoder, err := newSource(*iface, *filter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

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
```

**Step 5: Vérifier**
```bash
GOOS=linux  go build ./capture/...
GOOS=windows go build ./capture/...
```

**Step 6: Commit**
```bash
git add capture/source_linux.go capture/source_windows.go capture/main.go capture/go.mod capture/go.sum
git commit -m "feat(capture): cross-platform main program (Linux AF_PACKET + Windows WinDivert)"
```

---

## Checklist finale

- [ ] `go work sync` sans erreur
- [ ] `GOOS=linux go build ./...` passe
- [ ] `GOOS=windows go build ./...` passe
- [ ] `GOOS=linux go test ./bpf/...` passe
- [ ] `GOOS=windows go test ./windivert/filter/...` passe
- [ ] `go generate ./windivert/filter/...` régénère `grammar.go` sans diff
- [ ] IDs des champs WinDivert vérifiés contre `winfilter.c`
- [ ] IOCTL codes vérifiés + CTL_CODE calculé correctement
- [ ] Structure `WINDIVERT_ADDRESS` vérifiée (taille 80 bytes ?)
- [ ] Layout `WINDIVERT_FILTER_OBJECT` vérifié
- [ ] Jump patching AND/OR validé contre comportement WinDivert réel
