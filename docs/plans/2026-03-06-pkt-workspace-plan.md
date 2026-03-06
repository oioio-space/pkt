# pkt workspace — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Go workspace cross-platform packet capture — WinDivert (Windows, pure Go, embedded .sys) + AF_PACKET (Linux) — compatible gopacket.

**Architecture:** 3 modules (`pkt/windivert`, `pkt/afpacket`, `pkt/capture`) dans un Go workspace. WinDivert : embed du driver `.sys`, protocole IOCTL pur Go via `x/sys/windows`, filter compiler full WinDivert 2.x (lexer + parser + bytecode). AF_PACKET : SOCK_RAW via `x/sys/unix`. Pattern `With*` pour les options.

**Tech Stack:** Go 1.22+, `github.com/google/gopacket`, `golang.org/x/sys/windows`, `golang.org/x/sys/unix`

**Références :** Source WinDivert 2.x : https://github.com/basil00/Divert — étudier `windivert.h`, `windivert_device.h`, `winfilter.c` pour les IOCTL codes, structures, et bytecode format. Référence Go : https://github.com/imgk/divert-go pour les constantes portées en Go.

---

## Epic 1 — Workspace Setup

### Task 1: go.work + modules init

**Files:**
- Create: `go.work`
- Create: `windivert/go.mod`
- Create: `afpacket/go.mod`
- Create: `capture/go.mod`

**Step 1: Initialiser le workspace**

```bash
go work init
go work use ./windivert ./afpacket ./capture
```

**Step 2: Créer les modules**

```bash
mkdir windivert afpacket capture

cd windivert
go mod init pkt/windivert
go get github.com/google/gopacket
go get golang.org/x/sys

cd ../afpacket
go mod init pkt/afpacket
go get github.com/google/gopacket
go get golang.org/x/sys

cd ../capture
go mod init pkt/capture
go get github.com/google/gopacket
```

**Step 3: Vérifier**

```bash
go work sync
```

Expected: pas d'erreur.

**Step 4: Commit**

```bash
git add go.work windivert/go.mod windivert/go.sum afpacket/go.mod afpacket/go.sum capture/go.mod capture/go.sum
git commit -m "chore: init go workspace with 3 modules"
```

---

## Epic 2 — pkt/afpacket (Linux)

> Tous les fichiers de ce package ont `//go:build linux` en première ligne.

### Task 2: afpacket — options + API publique

**Files:**
- Create: `afpacket/afpacket.go`

**Step 1: Écrire le test**

`afpacket/afpacket_test.go` :
```go
//go:build linux

package afpacket_test

import (
	"testing"
	"pkt/afpacket"
)

func TestOpenOptions(t *testing.T) {
	// Test que les options compilent et sont appliquées
	opts := afpacket.defaultOptions()
	afpacket.WithPromiscuous(true)(&opts)
	afpacket.WithSnapLen(1500)(&opts)
	if !opts.Promiscuous { t.Error("promiscuous not set") }
	if opts.SnapLen != 1500 { t.Error("snaplen not set") }
}
```

**Step 2: Run test (FAIL)**
```bash
cd afpacket && GOOS=linux go test ./... 2>&1
```
Expected: FAIL — `afpacket` not defined.

**Step 3: Écrire `afpacket/afpacket.go`**

```go
//go:build linux

package afpacket

import "github.com/google/gopacket"

// Option configure un Handle.
type Option func(*options)

type options struct {
	SnapLen     int
	Promiscuous bool
}

func defaultOptions() options {
	return options{SnapLen: 65535, Promiscuous: true}
}

// WithSnapLen définit la taille maximale des paquets capturés.
func WithSnapLen(n int) Option { return func(o *options) { o.SnapLen = n } }

// WithPromiscuous active/désactive le mode promiscuous.
func WithPromiscuous(b bool) Option { return func(o *options) { o.Promiscuous = b } }

// Handle représente un socket AF_PACKET ouvert.
type Handle struct {
	fd   int
	opts options
}

// Open ouvre un socket AF_PACKET sur l'interface donnée.
func Open(iface string, opts ...Option) (*Handle, error) {
	o := defaultOptions()
	for _, opt := range opts { opt(&o) }
	return open(iface, o)
}

// Close ferme le socket.
func (h *Handle) Close() error { return closeHandle(h) }

// ReadPacketData implémente gopacket.PacketDataSource.
func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return readPacket(h)
}

// LinkType retourne le type de lien (Ethernet).
func (h *Handle) LinkType() gopacket.Decoder { return linkType() }
```

**Step 4: Run test (PASS)**
```bash
GOOS=linux go test ./... 2>&1
```

**Step 5: Commit**
```bash
git add afpacket/afpacket.go afpacket/afpacket_test.go
git commit -m "feat(afpacket): add public API + options"
```

---

### Task 3: afpacket — socket + bind

**Files:**
- Create: `afpacket/socket.go`

**Step 1: Écrire le test unitaire**

`afpacket/socket_test.go` :
```go
//go:build linux

package afpacket

import (
	"testing"
	"golang.org/x/sys/unix"
)

func TestIfIndex(t *testing.T) {
	// "lo" existe toujours sous Linux
	idx, err := ifaceIndex("lo")
	if err != nil { t.Fatal(err) }
	if idx == 0 { t.Error("ifaceIndex returned 0 for lo") }
}
```

**Step 2: Run test (FAIL)**
```bash
GOOS=linux go test -run TestIfIndex ./... 2>&1
```

**Step 3: Écrire `afpacket/socket.go`**

```go
//go:build linux

package afpacket

import (
	"fmt"
	"unsafe"
	"golang.org/x/sys/unix"
)

// htons convertit un uint16 host→network byte order.
func htons(i uint16) uint16 { return (i<<8) | (i>>8) }

func ifaceIndex(iface string) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil { return 0, fmt.Errorf("socket: %w", err) }
	defer unix.Close(fd)
	var ifreq [unix.IFNAMSIZ]byte
	copy(ifreq[:], iface)
	type ifreqIndex struct {
		name  [unix.IFNAMSIZ]byte
		index int32
		_     [20]byte
	}
	req := ifreqIndex{name: ifreq}
	const SIOCGIFINDEX = 0x8933
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		SIOCGIFINDEX, uintptr(unsafe.Pointer(&req))); errno != 0 {
		return 0, fmt.Errorf("SIOCGIFINDEX %s: %w", iface, errno)
	}
	return int(req.index), nil
}

func open(iface string, o options) (*Handle, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil { return nil, fmt.Errorf("socket: %w", err) }
	ifIdx, err := ifaceIndex(iface)  // reuse fd approach via another socket
	if err != nil { unix.Close(fd); return nil, err }
	sll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifIdx,
	}
	if err := unix.Bind(fd, &sll); err != nil {
		unix.Close(fd); return nil, fmt.Errorf("bind: %w", err)
	}
	h := &Handle{fd: fd, opts: o}
	if o.Promiscuous {
		if err := setPromiscuous(fd, ifIdx, true); err != nil {
			unix.Close(fd); return nil, err
		}
	}
	return h, nil
}

func closeHandle(h *Handle) error { return unix.Close(h.fd) }
```

**Note:** `ifaceIndex` utilise un syscall IOCTL direct. Alternative : utiliser `net.InterfaceByName` (stdlib) pour simplifier si suffisant.

**Step 4: Run test (PASS)**
```bash
GOOS=linux go test -run TestIfIndex ./...
```

**Step 5: Commit**
```bash
git add afpacket/socket.go afpacket/socket_test.go
git commit -m "feat(afpacket): AF_PACKET socket creation + bind"
```

---

### Task 4: afpacket — promiscuous + recv

**Files:**
- Create: `afpacket/promiscuous.go`
- Create: `afpacket/source.go`

**Step 1: `afpacket/promiscuous.go`**

```go
//go:build linux

package afpacket

import "golang.org/x/sys/unix"

func setPromiscuous(fd, ifIdx int, enable bool) error {
	mr := unix.PacketMreq{
		Ifindex: int32(ifIdx),
		Type:    unix.PACKET_MR_PROMISC,
	}
	opt := unix.PACKET_ADD_MEMBERSHIP
	if !enable { opt = unix.PACKET_DROP_MEMBERSHIP }
	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, opt, &mr)
}
```

**Step 2: `afpacket/source.go`**

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
	if err != nil { return nil, gopacket.CaptureInfo{}, err }
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: n,
		Length:        n,
	}
	return buf[:n], ci, nil
}

func linkType() gopacket.Decoder { return layers.LayerTypeEthernet }
```

**Step 3: Commit**
```bash
git add afpacket/promiscuous.go afpacket/source.go
git commit -m "feat(afpacket): recv + promiscuous mode"
```

---

## Epic 3 — pkt/windivert (Windows)

> Tous les fichiers ont `//go:build windows`. Étudier le source WinDivert 2.x AVANT de coder les IOCTL codes et structures.

### Task 5: windivert — constantes + structures

**Files:**
- Create: `windivert/const.go`
- Create: `windivert/address.go`

**Référence obligatoire :** Lire `windivert.h` et `windivert_device.h` sur https://github.com/basil00/Divert avant d'écrire ce fichier. Les valeurs ci-dessous sont indicatives.

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

// Flags pour WinDivertOpen.
const (
	FlagSniff    uint64 = 1 << 0
	FlagDrop     uint64 = 1 << 1
	FlagRecvOnly uint64 = 1 << 2
	FlagSendOnly uint64 = 1 << 3
	FlagNoInstall uint64 = 1 << 4
	FlagFragments uint64 = 1 << 5
)

// IOCTL codes — vérifier avec windivert_device.h.
// CTL_CODE(FILE_DEVICE_NETWORK=0x12, func, method, access)
// method: METHOD_BUFFERED=0, METHOD_IN_DIRECT=1, METHOD_OUT_DIRECT=2
// access: FILE_ANY_ACCESS=0, FILE_READ=1, FILE_WRITE=2
const (
	ioctlInitialize = 0x12000C // à vérifier dans windivert_device.h
	ioctlStartup    = 0x12001C // à vérifier
	ioctlShutdown   = 0x12002C // à vérifier
	ioctlSetParam   = 0x12003C // à vérifier
	ioctlGetParam   = 0x12004C // à vérifier
)

// Device path (WinDivert 2.x).
const devicePath = `\\.\WinDivert`
```

**Step 2: `windivert/address.go`**

```go
//go:build windows

package windivert

// Address contient les métadonnées d'un paquet WinDivert.
// Correspond à WINDIVERT_ADDRESS dans windivert.h.
// VÉRIFIER la structure exacte dans windivert.h (v2.x).
type Address struct {
	Timestamp int64  // WINDIVERT_ADDRESS.Timestamp (LARGE_INTEGER)
	// Champs bitfield — vérifier layout exact
	Layer     uint8
	Event     uint8
	Flags     uint8  // Sniff, Outbound, Loopback, Impostor, IPv6, ChecksumOK*
	Reserved  uint8
	// Union selon Layer (Network, Flow, Socket, Reflect)
	// Pour LayerNetwork :
	Network struct {
		IfIdx    uint32
		SubIfIdx uint32
	}
	_ [48]byte // padding pour couvrir la taille union (vérifier sizeof)
}

// IsOutbound retourne true si le paquet est sortant.
func (a *Address) IsOutbound() bool { return a.Flags&0x04 != 0 } // bit à vérifier

// IsLoopback retourne true si le paquet est loopback.
func (a *Address) IsLoopback() bool { return a.Flags&0x08 != 0 } // bit à vérifier
```

**Step 3: Commit**
```bash
git add windivert/const.go windivert/address.go
git commit -m "feat(windivert): constants + WINDIVERT_ADDRESS structure"
```

---

### Task 6: windivert/filter — lexer

**Files:**
- Create: `windivert/filter/token.go`
- Create: `windivert/filter/lexer.go`

**Step 1: Écrire le test du lexer**

`windivert/filter/lexer_test.go` :
```go
//go:build windows

package filter

import (
	"testing"
)

func TestLexer(t *testing.T) {
	cases := []struct {
		input  string
		tokens []TokenType
	}{
		{"true", []TokenType{TRUE, EOF}},
		{"false", []TokenType{FALSE, EOF}},
		{"ip", []TokenType{IDENT, EOF}},
		{"tcp.DstPort == 80", []TokenType{IDENT, DOT, IDENT, EQ, NUMBER, EOF}},
		{"!tcp", []TokenType{NOT, IDENT, EOF}},
		{"ip and tcp", []TokenType{IDENT, AND, IDENT, EOF}},
		{"ip or udp", []TokenType{IDENT, OR, IDENT, EOF}},
		{"(ip)", []TokenType{LPAREN, IDENT, RPAREN, EOF}},
		{"tcp.SrcPort != 443", []TokenType{IDENT, DOT, IDENT, NEQ, NUMBER, EOF}},
		{"ip.SrcAddr == 192.168.1.1", []TokenType{IDENT, DOT, IDENT, EQ, IPADDR, EOF}},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			l := NewLexer(c.input)
			for i, want := range c.tokens {
				tok := l.Next()
				if tok.Type != want {
					t.Fatalf("token[%d]: got %v want %v", i, tok.Type, want)
				}
			}
		})
	}
}
```

**Step 2: Run test (FAIL)**
```bash
GOOS=windows go test ./windivert/filter/... 2>&1
```

**Step 3: Écrire `windivert/filter/token.go`**

```go
//go:build windows

package filter

// TokenType identifie le type d'un token.
type TokenType int

const (
	EOF TokenType = iota
	ERROR
	IDENT   // ip, tcp, DstPort, ...
	NUMBER  // 80, 443, 0x1A, ...
	IPADDR  // 192.168.1.1
	IP6ADDR // ::1, fe80::...
	STRING  // "text"
	TRUE
	FALSE
	AND  // and &&
	OR   // or ||
	NOT  // ! not
	EQ   // ==
	NEQ  // !=
	LT   // <
	LE   // <=
	GT   // >
	GE   // >=
	DOT     // .
	LPAREN  // (
	RPAREN  // )
	COLON   // :  (pour IPv6)
)

// Token est un token du filtre WinDivert.
type Token struct {
	Type  TokenType
	Value string // valeur textuelle
}
```

**Step 4: Écrire `windivert/filter/lexer.go`**

```go
//go:build windows

package filter

import (
	"strings"
	"unicode"
)

// Lexer tokenise un filtre WinDivert 2.x.
type Lexer struct {
	input []rune
	pos   int
}

// NewLexer crée un Lexer pour la chaîne filtre.
func NewLexer(input string) *Lexer { return &Lexer{input: []rune(input)} }

func (l *Lexer) peek() rune {
	if l.pos >= len(l.input) { return 0 }
	return l.input[l.pos]
}

func (l *Lexer) advance() rune {
	r := l.peek(); l.pos++; return r
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) && unicode.IsSpace(l.input[l.pos]) { l.pos++ }
}

// Next retourne le prochain token.
func (l *Lexer) Next() Token {
	l.skipWhitespace()
	if l.pos >= len(l.input) { return Token{EOF, ""} }

	r := l.peek()

	// Opérateurs multi-caractères
	switch r {
	case '=':
		l.advance()
		if l.peek() == '=' { l.advance(); return Token{EQ, "=="} }
		return Token{ERROR, "="}
	case '!':
		l.advance()
		if l.peek() == '=' { l.advance(); return Token{NEQ, "!="} }
		return Token{NOT, "!"}
	case '<':
		l.advance()
		if l.peek() == '=' { l.advance(); return Token{LE, "<="} }
		return Token{LT, "<"}
	case '>':
		l.advance()
		if l.peek() == '=' { l.advance(); return Token{GE, ">="} }
		return Token{GT, ">"}
	case '(': l.advance(); return Token{LPAREN, "("}
	case ')': l.advance(); return Token{RPAREN, ")"}
	case '.': l.advance(); return Token{DOT, "."}
	}

	// Nombres et adresses IP
	if unicode.IsDigit(r) {
		return l.lexNumber()
	}

	// Identifiants et mots-clés
	if unicode.IsLetter(r) || r == '_' {
		return l.lexIdent()
	}

	l.advance()
	return Token{ERROR, string(r)}
}

func (l *Lexer) lexIdent() Token {
	start := l.pos
	for l.pos < len(l.input) {
		r := l.input[l.pos]
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' { break }
		l.pos++
	}
	val := string(l.input[start:l.pos])
	switch strings.ToLower(val) {
	case "true":  return Token{TRUE, val}
	case "false": return Token{FALSE, val}
	case "and":   return Token{AND, val}
	case "or":    return Token{OR, val}
	case "not":   return Token{NOT, val}
	}
	return Token{IDENT, val}
}

func (l *Lexer) lexNumber() Token {
	start := l.pos
	// Hex
	if l.input[start] == '0' && l.pos+1 < len(l.input) &&
		(l.input[l.pos+1] == 'x' || l.input[l.pos+1] == 'X') {
		l.pos += 2
		for l.pos < len(l.input) && isHexDigit(l.input[l.pos]) { l.pos++ }
		return Token{NUMBER, string(l.input[start:l.pos])}
	}
	// Décimal, potentiellement IP
	dots := 0
	for l.pos < len(l.input) {
		r := l.input[l.pos]
		if unicode.IsDigit(r) { l.pos++; continue }
		if r == '.' && l.pos+1 < len(l.input) && unicode.IsDigit(l.input[l.pos+1]) {
			dots++; l.pos++; continue
		}
		break
	}
	val := string(l.input[start:l.pos])
	if dots == 3 { return Token{IPADDR, val} }
	return Token{NUMBER, val}
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
```

**Step 5: Run test (PASS)**
```bash
GOOS=windows go test ./windivert/filter/... -run TestLexer -v
```

**Step 6: Commit**
```bash
git add windivert/filter/token.go windivert/filter/lexer.go windivert/filter/lexer_test.go
git commit -m "feat(windivert/filter): lexer tokenizer"
```

---

### Task 7: windivert/filter — parser + AST

**Files:**
- Create: `windivert/filter/ast.go`
- Create: `windivert/filter/parser.go`

**Step 1: Écrire le test du parser**

`windivert/filter/parser_test.go` :
```go
//go:build windows

package filter

import "testing"

func TestParser(t *testing.T) {
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
		{"==", true},   // invalid
		{"ip and", true}, // incomplete
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			_, err := Parse(c.input)
			if (err != nil) != c.wantErr {
				t.Fatalf("Parse(%q): err=%v wantErr=%v", c.input, err, c.wantErr)
			}
		})
	}
}
```

**Step 2: Écrire `windivert/filter/ast.go`**

```go
//go:build windows

package filter

// Node est un nœud de l'AST du filtre.
type Node interface{ nodeKind() string }

// BoolNode représente les littéraux true/false.
type BoolNode struct{ Value bool }
func (n *BoolNode) nodeKind() string { return "bool" }

// FieldNode représente un champ seul (ex: "ip", "tcp") — test d'existence.
type FieldNode struct{ Parts []string } // ["ip"] ou ["tcp", "DstPort"]
func (n *FieldNode) nodeKind() string { return "field" }

// CmpNode représente une comparaison (field op value).
type CmpNode struct {
	Field []string   // ["tcp", "DstPort"]
	Op    TokenType  // EQ, NEQ, LT, LE, GT, GE
	Value string     // valeur brute
	VTok  TokenType  // NUMBER, IPADDR, IP6ADDR
}
func (n *CmpNode) nodeKind() string { return "cmp" }

// BinaryNode représente AND/OR.
type BinaryNode struct {
	Op          TokenType // AND, OR
	Left, Right Node
}
func (n *BinaryNode) nodeKind() string { return "binary" }

// UnaryNode représente NOT.
type UnaryNode struct{ Child Node }
func (n *UnaryNode) nodeKind() string { return "unary" }
```

**Step 3: Écrire `windivert/filter/parser.go`**

```go
//go:build windows

package filter

import "fmt"

// Parser transforme les tokens en AST.
type Parser struct {
	lexer   *Lexer
	current Token
	peeked  Token
	hasPeek bool
}

// Parse parse une chaîne filtre WinDivert et retourne l'AST.
func Parse(input string) (Node, error) {
	p := &Parser{lexer: NewLexer(input)}
	p.advance()
	node, err := p.parseOr()
	if err != nil { return nil, err }
	if p.current.Type != EOF {
		return nil, fmt.Errorf("unexpected token: %q", p.current.Value)
	}
	return node, nil
}

func (p *Parser) advance() { p.current = p.lexer.Next() }

// parseOr : or_expr := and_expr ('or' and_expr)*
func (p *Parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil { return nil, err }
	for p.current.Type == OR {
		p.advance()
		right, err := p.parseAnd()
		if err != nil { return nil, err }
		left = &BinaryNode{Op: OR, Left: left, Right: right}
	}
	return left, nil
}

// parseAnd : and_expr := not_expr ('and' not_expr)*
func (p *Parser) parseAnd() (Node, error) {
	left, err := p.parseNot()
	if err != nil { return nil, err }
	for p.current.Type == AND {
		p.advance()
		right, err := p.parseNot()
		if err != nil { return nil, err }
		left = &BinaryNode{Op: AND, Left: left, Right: right}
	}
	return left, nil
}

// parseNot : not_expr := '!' not_expr | primary
func (p *Parser) parseNot() (Node, error) {
	if p.current.Type == NOT {
		p.advance()
		child, err := p.parseNot()
		if err != nil { return nil, err }
		return &UnaryNode{Child: child}, nil
	}
	return p.parsePrimary()
}

// parsePrimary : '(' expr ')' | 'true' | 'false' | field [op value]
func (p *Parser) parsePrimary() (Node, error) {
	switch p.current.Type {
	case LPAREN:
		p.advance()
		node, err := p.parseOr()
		if err != nil { return nil, err }
		if p.current.Type != RPAREN {
			return nil, fmt.Errorf("expected ')' got %q", p.current.Value)
		}
		p.advance()
		return node, nil
	case TRUE:
		p.advance()
		return &BoolNode{true}, nil
	case FALSE:
		p.advance()
		return &BoolNode{false}, nil
	case IDENT:
		return p.parseFieldOrCmp()
	}
	return nil, fmt.Errorf("unexpected token: %q (type %v)", p.current.Value, p.current.Type)
}

func (p *Parser) parseFieldOrCmp() (Node, error) {
	parts := []string{p.current.Value}
	p.advance()
	for p.current.Type == DOT {
		p.advance()
		if p.current.Type != IDENT {
			return nil, fmt.Errorf("expected field name after '.'")
		}
		parts = append(parts, p.current.Value)
		p.advance()
	}
	// Comparaison ?
	switch p.current.Type {
	case EQ, NEQ, LT, LE, GT, GE:
		op := p.current.Type
		p.advance()
		if p.current.Type != NUMBER && p.current.Type != IPADDR && p.current.Type != IP6ADDR {
			return nil, fmt.Errorf("expected value after operator, got %q", p.current.Value)
		}
		node := &CmpNode{Field: parts, Op: op, Value: p.current.Value, VTok: p.current.Type}
		p.advance()
		return node, nil
	}
	return &FieldNode{Parts: parts}, nil
}
```

**Step 4: Run test (PASS)**
```bash
GOOS=windows go test ./windivert/filter/... -run TestParser -v
```

**Step 5: Commit**
```bash
git add windivert/filter/ast.go windivert/filter/parser.go windivert/filter/parser_test.go
git commit -m "feat(windivert/filter): recursive descent parser + AST"
```

---

### Task 8: windivert/filter — fields table

**Files:**
- Create: `windivert/filter/fields.go`

**Référence:** `winfilter.c` dans WinDivert source — table `winDivertFilterFields`.

**Step 1: Écrire le test**

`windivert/filter/fields_test.go` :
```go
//go:build windows

package filter

import "testing"

func TestFieldLookup(t *testing.T) {
	cases := []struct {
		parts []string
		ok    bool
	}{
		{[]string{"ip", "SrcAddr"}, true},
		{[]string{"tcp", "DstPort"}, true},
		{[]string{"udp", "SrcPort"}, true},
		{[]string{"icmp", "Type"}, true},
		{[]string{"ip"}, true},  // field existence check
		{[]string{"tcp"}, true},
		{[]string{"unknown"}, false},
		{[]string{"tcp", "UnknownField"}, false},
	}
	for _, c := range cases {
		_, err := LookupField(c.parts)
		if (err == nil) != c.ok {
			t.Errorf("LookupField(%v): got err=%v want ok=%v", c.parts, err, c.ok)
		}
	}
}
```

**Step 2: Écrire `windivert/filter/fields.go`**

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
	KindBool   FieldKind = iota // 1 bit
	KindUint8                   // UINT8
	KindUint16                  // UINT16 (réseau byte order)
	KindUint32                  // UINT32
	KindUint64                  // UINT64
	KindIPv4                    // 32-bit IP
	KindIPv6                    // 128-bit IP
)

// FieldDef définit un champ WinDivert connu.
type FieldDef struct {
	ID   uint32    // identifiant dans le bytecode (vérifier dans WinDivert source)
	Kind FieldKind
}

// fieldTable est la table des champs WinDivert 2.x.
// IDs à vérifier dans winfilter.c (WINDIVERT_FILTER_FIELD_*).
var fieldTable = map[string]FieldDef{
	// Champs globaux
	"Zero":      {0, KindUint8},
	"Event":     {1, KindUint8},
	"Random8":   {2, KindUint8},
	"Random16":  {3, KindUint16},
	"Random32":  {4, KindUint32},
	"Timestamp": {5, KindUint64},
	"Length":    {6, KindUint16},
	// IPv4
	"ip":                {10, KindBool},  // existence
	"ip.HdrLength":      {11, KindUint8},
	"ip.TOS":            {12, KindUint8},
	"ip.Length":         {13, KindUint16},
	"ip.Id":             {14, KindUint16},
	"ip.MF":             {15, KindBool},
	"ip.FragOff":        {16, KindUint16},
	"ip.TTL":            {17, KindUint8},
	"ip.Protocol":       {18, KindUint8},
	"ip.Checksum":       {19, KindUint16},
	"ip.SrcAddr":        {20, KindIPv4},
	"ip.DstAddr":        {21, KindIPv4},
	// IPv6
	"ipv6":              {30, KindBool},
	"ipv6.TrafficClass": {31, KindUint8},
	"ipv6.FlowLabel":    {32, KindUint32},
	"ipv6.Length":       {33, KindUint16},
	"ipv6.NextHdr":      {34, KindUint8},
	"ipv6.HopLimit":     {35, KindUint8},
	"ipv6.SrcAddr":      {36, KindIPv6},
	"ipv6.DstAddr":      {37, KindIPv6},
	// TCP
	"tcp":               {40, KindBool},
	"tcp.SrcPort":       {41, KindUint16},
	"tcp.DstPort":       {42, KindUint16},
	"tcp.SeqNum":        {43, KindUint32},
	"tcp.AckNum":        {44, KindUint32},
	"tcp.HdrLength":     {45, KindUint8},
	"tcp.Ns":            {46, KindBool},
	"tcp.Cwr":           {47, KindBool},
	"tcp.Ece":           {48, KindBool},
	"tcp.Urg":           {49, KindBool},
	"tcp.Ack":           {50, KindBool},
	"tcp.Psh":           {51, KindBool},
	"tcp.Rst":           {52, KindBool},
	"tcp.Syn":           {53, KindBool},
	"tcp.Fin":           {54, KindBool},
	"tcp.Window":        {55, KindUint16},
	"tcp.Checksum":      {56, KindUint16},
	"tcp.UrgPtr":        {57, KindUint16},
	"tcp.PayloadLength": {58, KindUint16},
	// UDP
	"udp":               {60, KindBool},
	"udp.SrcPort":       {61, KindUint16},
	"udp.DstPort":       {62, KindUint16},
	"udp.Length":        {63, KindUint16},
	"udp.Checksum":      {64, KindUint16},
	"udp.PayloadLength": {65, KindUint16},
	// ICMP
	"icmp":              {70, KindBool},
	"icmp.Type":         {71, KindUint8},
	"icmp.Code":         {72, KindUint8},
	"icmp.Checksum":     {73, KindUint16},
	"icmp.Body":         {74, KindUint32},
	// ICMPv6
	"icmpv6":            {80, KindBool},
	"icmpv6.Type":       {81, KindUint8},
	"icmpv6.Code":       {82, KindUint8},
	"icmpv6.Checksum":   {83, KindUint16},
	"icmpv6.Body":       {84, KindUint32},
}

// LookupField recherche la définition d'un champ par ses parts (ex: ["tcp","DstPort"]).
func LookupField(parts []string) (FieldDef, error) {
	key := strings.Join(parts, ".")
	def, ok := fieldTable[key]
	if !ok {
		return FieldDef{}, fmt.Errorf("unknown field: %q", key)
	}
	return def, nil
}
```

**Step 3: Run test (PASS)**
```bash
GOOS=windows go test ./windivert/filter/... -run TestFieldLookup -v
```

**⚠️ Important :** Les IDs des champs ci-dessus sont des placeholders. Avant d'implémenter le compiler (Task 9), vérifier les IDs réels dans le source WinDivert.

**Step 4: Commit**
```bash
git add windivert/filter/fields.go windivert/filter/fields_test.go
git commit -m "feat(windivert/filter): WinDivert 2.x field table"
```

---

### Task 9: windivert/filter — bytecode compiler

**Files:**
- Create: `windivert/filter/compiler.go`

**Référence:** Structure `WINDIVERT_FILTER_OBJECT` dans `windivert_device.h`. Le compilateur génère un tableau d'objets avec short-circuit evaluation via success/failure jumps.

**Step 1: Écrire le test**

`windivert/filter/compiler_test.go` :
```go
//go:build windows

package filter

import "testing"

func TestCompile(t *testing.T) {
	cases := []struct {
		filter  string
		wantErr bool
		minLen  int // nombre minimum d'objets attendus
	}{
		{"true", false, 1},
		{"false", false, 1},
		{"ip", false, 1},
		{"tcp.DstPort == 80", false, 1},
		{"ip and tcp", false, 2},
		{"ip or udp", false, 2},
		{"!tcp", false, 1},
		{"tcp.DstPort == 80 and ip.SrcAddr == 192.168.1.1", false, 2},
		{"unknown.Field == 1", true, 0},
	}
	for _, c := range cases {
		t.Run(c.filter, func(t *testing.T) {
			prog, err := Compile(c.filter)
			if (err != nil) != c.wantErr {
				t.Fatalf("Compile(%q): err=%v wantErr=%v", c.filter, err, c.wantErr)
			}
			if !c.wantErr && len(prog) < c.minLen {
				t.Errorf("Compile(%q): got %d objects, want >= %d", c.filter, len(prog), c.minLen)
			}
		})
	}
}
```

**Step 2: Écrire `windivert/filter/compiler.go`**

```go
//go:build windows

package filter

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// FilterObject est un objet bytecode WinDivert.
// Vérifier la structure exacte dans windivert_device.h.
type FilterObject struct {
	Val     [4]uint32 // valeur de comparaison (128 bits)
	Field   uint32    // ID du champ (24 bits utilisés)
	Test    uint8     // type de test (EQ=0, NEQ=1, LT=2, LE=3, GT=4, GE=5, TRUE=6, FALSE=7)
	Neg     uint8     // 1 si négation
	Success uint16    // saut si succès (index relatif)
	Failure uint16    // saut si échec (index relatif)
}

// Tests
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

// Compile compile un filtre WinDivert en bytecode.
func Compile(filter string) ([]FilterObject, error) {
	ast, err := Parse(filter)
	if err != nil { return nil, fmt.Errorf("parse: %w", err) }
	c := &compiler{}
	if err := c.emit(ast); err != nil { return nil, fmt.Errorf("compile: %w", err) }
	return c.prog, nil
}

type compiler struct {
	prog []FilterObject
}

func (c *compiler) emit(n Node) error {
	switch node := n.(type) {
	case *BoolNode:
		obj := FilterObject{Test: testTrue}
		if !node.Value { obj.Test = testFalse }
		c.prog = append(c.prog, obj)
	case *FieldNode:
		def, err := LookupField(node.Parts)
		if err != nil { return err }
		obj := FilterObject{Field: def.ID, Test: testTrue}
		c.prog = append(c.prog, obj)
	case *CmpNode:
		if err := c.emitCmp(node); err != nil { return err }
	case *UnaryNode:
		if err := c.emit(node.Child); err != nil { return err }
		// Inverser Success/Failure du dernier objet
		last := &c.prog[len(c.prog)-1]
		last.Success, last.Failure = last.Failure, last.Success
		last.Neg ^= 1
	case *BinaryNode:
		if err := c.emitBinary(node); err != nil { return err }
	default:
		return fmt.Errorf("unknown AST node type: %T", n)
	}
	return nil
}

func (c *compiler) emitCmp(n *CmpNode) error {
	def, err := LookupField(n.Field)
	if err != nil { return err }
	val, err := parseValue(n.Value, n.VTok, def.Kind)
	if err != nil { return err }
	obj := FilterObject{Field: def.ID, Val: val, Test: tokenToTest(n.Op)}
	c.prog = append(c.prog, obj)
	return nil
}

func (c *compiler) emitBinary(n *BinaryNode) error {
	// Pour AND : si left échoue, court-circuit → FAIL global
	// Pour OR  : si left réussit, court-circuit → SUCCESS global
	// Implémentation simplifiée : émettre left puis right avec jumps
	startLeft := len(c.prog)
	if err := c.emit(n.Left); err != nil { return err }
	endLeft := len(c.prog)
	if err := c.emit(n.Right); err != nil { return err }

	// Patch des jumps de gauche vers droite
	// (implémentation simpliste — les jumps WinDivert sont relatifs)
	_ = startLeft; _ = endLeft
	// TODO: implémenter le patching des jumps selon la spec WinDivert
	// Les jumps success/failure pointent vers l'index de la prochaine instruction
	// à vérifier dans winfilter.c
	if n.Op == AND {
		// left failure → FAIL total (jump à la fin)
		// left success → évaluer right
	} else { // OR
		// left success → SUCCESS total
		// left failure → évaluer right
	}
	return nil
}

func tokenToTest(t TokenType) uint8 {
	switch t {
	case EQ:  return testEQ
	case NEQ: return testNEQ
	case LT:  return testLT
	case LE:  return testLE
	case GT:  return testGT
	case GE:  return testGE
	}
	return testTrue
}

func parseValue(raw string, tok TokenType, kind FieldKind) ([4]uint32, error) {
	var val [4]uint32
	switch tok {
	case NUMBER:
		raw = strings.TrimPrefix(raw, "0x")
		raw = strings.TrimPrefix(raw, "0X")
		n, err := strconv.ParseUint(raw, 0, 64)
		if err != nil { return val, fmt.Errorf("invalid number %q: %w", raw, err) }
		val[0] = uint32(n)
		val[1] = uint32(n >> 32)
	case IPADDR:
		ip := net.ParseIP(raw).To4()
		if ip == nil { return val, fmt.Errorf("invalid IPv4: %q", raw) }
		val[0] = binary.BigEndian.Uint32(ip)
	case IP6ADDR:
		ip := net.ParseIP(raw).To16()
		if ip == nil { return val, fmt.Errorf("invalid IPv6: %q", raw) }
		val[0] = binary.BigEndian.Uint32(ip[0:4])
		val[1] = binary.BigEndian.Uint32(ip[4:8])
		val[2] = binary.BigEndian.Uint32(ip[8:12])
		val[3] = binary.BigEndian.Uint32(ip[12:16])
	}
	return val, nil
}
```

**⚠️ Note :** Le patching des jumps AND/OR (section `emitBinary`) est marqué TODO — implémenter après avoir étudié `winfilter.c` pour comprendre exactement comment les jumps success/failure sont calculés. Le reste (CmpNode, UnaryNode, BoolNode) peut être validé sans les jumps complexes.

**Step 3: Run test (PASS partiellement)**
```bash
GOOS=windows go test ./windivert/filter/... -v
```

**Step 4: Commit**
```bash
git add windivert/filter/compiler.go windivert/filter/compiler_test.go
git commit -m "feat(windivert/filter): bytecode compiler (WIP binary jumps)"
```

---

### Task 10: windivert — driver installer

**Files:**
- Create: `windivert/driver/installer.go`
- Create: `windivert/assets/` (répertoire avec WinDivert64.sys)

**⚠️ WinDivert64.sys** : Ce fichier binaire doit être téléchargé depuis les releases WinDivert 2.x (https://github.com/basil00/Divert/releases) et placé dans `windivert/assets/`. Il est sous licence LGPL.

**Step 1: Écrire `windivert/driver/installer.go`**

```go
//go:build windows

package driver

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WinDivert"

// Install extrait le .sys depuis les données embedées et installe le driver SCM.
// Idempotent : retourne nil si déjà installé.
func Install(sysData []byte) error {
	sysPath, err := extractSys(sysData)
	if err != nil { return fmt.Errorf("extract sys: %w", err) }
	return installService(sysPath)
}

// Uninstall arrête et supprime le service WinDivert.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil { return fmt.Errorf("SCM connect: %w", err) }
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil { return nil } // pas installé
	defer s.Close()
	_ = s.Control(windows.SERVICE_CONTROL_STOP) // ignorer l'erreur si déjà arrêté
	return s.Delete()
}

func extractSys(data []byte) (string, error) {
	dir, err := os.MkdirTemp("", "windivert-")
	if err != nil { return "", err }
	path := filepath.Join(dir, "WinDivert64.sys")
	return path, os.WriteFile(path, data, 0600)
}

func installService(sysPath string) error {
	m, err := mgr.Connect()
	if err != nil { return fmt.Errorf("SCM connect: %w", err) }
	defer m.Disconnect()

	// Vérifier si le service existe déjà
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		return startIfStopped(s)
	}

	// Créer le service
	cfg := mgr.Config{
		ServiceType:  windows.SERVICE_KERNEL_DRIVER,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "WinDivert Network Driver",
	}
	s, err = m.CreateService(serviceName, sysPath, cfg)
	if err != nil { return fmt.Errorf("CreateService: %w", err) }
	defer s.Close()
	return s.Start()
}

func startIfStopped(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil { return err }
	if status.State == windows.SERVICE_RUNNING { return nil }
	return s.Start()
}

// OpenDevice ouvre le device WinDivert et retourne un handle Windows.
func OpenDevice(layer uint32) (windows.Handle, error) {
	path := `\\.\WinDivert` // WinDivert 2.x — vérifier le path exact
	name, err := windows.UTF16PtrFromString(path)
	if err != nil { return 0, err }
	h, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil { return 0, fmt.Errorf("CreateFile %s: %w", path, err) }
	_ = unsafe.Pointer(nil) // éviter import inutilisé
	return h, nil
}
```

**Step 2: Créer le répertoire assets + embed**

`windivert/assets/embed.go` :
```go
//go:build windows

package assets

import _ "embed"

// Sys64 contient le binaire WinDivert64.sys.
// Télécharger depuis https://github.com/basil00/Divert/releases
//go:embed WinDivert64.sys
var Sys64 []byte
```

**Step 3: Commit**
```bash
git add windivert/driver/installer.go windivert/assets/embed.go
git commit -m "feat(windivert/driver): SCM driver installer + device open"
```

---

### Task 11: windivert — handle + overlapped I/O

**Files:**
- Create: `windivert/handle.go`

**Step 1: Écrire `windivert/handle.go`**

```go
//go:build windows

package windivert

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"pkt/windivert/filter"
)

// Handle représente un handle WinDivert ouvert.
type Handle struct {
	win   windows.Handle
	layer Layer
	opts  options
}

func newHandle(win windows.Handle, layer Layer, o options) *Handle {
	return &Handle{win: win, layer: layer, opts: o}
}

// Close ferme le handle WinDivert.
func (h *Handle) Close() error {
	return windows.CloseHandle(h.win)
}

// Recv reçoit un paquet depuis WinDivert.
// Retourne les données brutes et l'adresse associée.
func (h *Handle) Recv(buf []byte) (int, *Address, error) {
	var addr Address
	var recvLen uint32
	ov := new(windows.Overlapped)
	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil { return 0, nil, fmt.Errorf("CreateEvent: %w", err) }
	defer windows.CloseHandle(ev)
	ov.HEvent = ev

	err = windows.ReadFile(h.win, buf, &recvLen, ov)
	if err != nil && err != windows.ERROR_IO_PENDING {
		return 0, nil, fmt.Errorf("ReadFile: %w", err)
	}
	if err == windows.ERROR_IO_PENDING {
		if _, err = windows.WaitForSingleObject(ev, windows.INFINITE); err != nil {
			return 0, nil, fmt.Errorf("WaitForSingleObject: %w", err)
		}
		if err = windows.GetOverlappedResult(h.win, ov, &recvLen, false); err != nil {
			return 0, nil, fmt.Errorf("GetOverlappedResult: %w", err)
		}
	}
	return int(recvLen), &addr, nil
}

// Send injecte un paquet via WinDivert.
func (h *Handle) Send(data []byte, addr *Address) error {
	var sent uint32
	return windows.WriteFile(h.win, data, &sent, nil)
}

// ioctl envoie un IOCTL au driver WinDivert.
func (h *Handle) ioctl(code uint32, in []byte, out []byte) error {
	var returned uint32
	var inPtr, outPtr *byte
	var inLen, outLen uint32
	if len(in) > 0 { inPtr = &in[0]; inLen = uint32(len(in)) }
	if len(out) > 0 { outPtr = &out[0]; outLen = uint32(len(out)) }
	return windows.DeviceIoControl(h.win, code, inPtr, inLen, outPtr, outLen, &returned, nil)
}

// initialize envoie le filtre compilé au driver et démarre la capture.
func (h *Handle) initialize(prog []filter.FilterObject, layer Layer, priority int16, flags uint64) error {
	// Structure WINDIVERT_IOCTL_INITIALIZE_DATA — vérifier dans windivert_device.h
	type initData struct {
		Layer    uint32
		Priority int16
		Flags    uint64
		// ... autres champs selon la spec
	}
	_ = initData{}
	// Sérialiser prog en bytes
	size := len(prog) * int(unsafe.Sizeof(filter.FilterObject{}))
	buf := make([]byte, size)
	for i, obj := range prog {
		off := i * int(unsafe.Sizeof(obj))
		copy(buf[off:], (*[unsafe.Sizeof(filter.FilterObject{})]byte)(unsafe.Pointer(&obj))[:])
	}
	if err := h.ioctl(ioctlInitialize, buf, nil); err != nil {
		return fmt.Errorf("IOCTL_INITIALIZE: %w", err)
	}
	return h.ioctl(ioctlStartup, nil, nil)
}
```

**Step 2: Commit**
```bash
git add windivert/handle.go
git commit -m "feat(windivert): overlapped I/O handle + IOCTL"
```

---

### Task 12: windivert — API publique + source gopacket

**Files:**
- Create: `windivert/windivert.go`
- Create: `windivert/source.go`

**Step 1: `windivert/windivert.go`**

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

// Option configure un Handle WinDivert.
type Option func(*options)

// WithSnapLen définit la taille max des paquets.
func WithSnapLen(n int) Option { return func(o *options) { o.SnapLen = n } }

// WithPriority définit la priorité (-30000..30000).
func WithPriority(p int16) Option { return func(o *options) { o.Priority = p } }

// WithFlags définit les flags WinDivert (FlagSniff, FlagDrop...).
func WithFlags(f uint64) Option { return func(o *options) { o.Flags = f } }

// Open installe le driver si nécessaire, compile le filtre, et ouvre un Handle.
func Open(filterStr string, layer Layer, opts ...Option) (*Handle, error) {
	o := defaultOptions()
	for _, opt := range opts { opt(&o) }

	// 1. Installer le driver
	if err := driver.Install(assets.Sys64); err != nil {
		return nil, fmt.Errorf("install driver: %w", err)
	}

	// 2. Compiler le filtre
	prog, err := filter.Compile(filterStr)
	if err != nil { return nil, fmt.Errorf("compile filter: %w", err) }

	// 3. Ouvrir le device
	winHandle, err := driver.OpenDevice(uint32(layer))
	if err != nil { return nil, fmt.Errorf("open device: %w", err) }

	h := newHandle(winHandle, layer, o)

	// 4. IOCTL initialize
	if err := h.initialize(prog, layer, o.Priority, o.Flags); err != nil {
		h.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	return h, nil
}
```

**Step 2: `windivert/source.go`**

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
	if err != nil { return nil, gopacket.CaptureInfo{}, err }
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: n,
		Length:        n,
	}
	return buf[:n], ci, nil
}

// LinkType retourne le decoder gopacket (IPv4 pour WinDivert Network layer).
func (h *Handle) LinkType() gopacket.Decoder { return layers.LayerTypeIPv4 }
```

**Step 3: Commit**
```bash
git add windivert/windivert.go windivert/source.go
git commit -m "feat(windivert): public Open API + gopacket PacketDataSource"
```

---

## Epic 4 — pkt/capture (cross-platform)

### Task 13: capture — main + sources par plateforme

**Files:**
- Create: `capture/source_linux.go`
- Create: `capture/source_windows.go`
- Create: `capture/main.go`

**Step 1: `capture/source_linux.go`**

```go
//go:build linux

package main

import (
	"github.com/google/gopacket"
	"pkt/afpacket"
)

func newSource(iface, _ string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	h, err := afpacket.Open(iface)
	if err != nil { return nil, nil, err }
	return h, h.LinkType(), nil
}
```

**Step 2: `capture/source_windows.go`**

```go
//go:build windows

package main

import (
	"github.com/google/gopacket"
	"pkt/windivert"
)

func newSource(_, filterStr string) (gopacket.PacketDataSource, gopacket.Decoder, error) {
	h, err := windivert.Open(filterStr, windivert.LayerNetwork)
	if err != nil { return nil, nil, err }
	return h, h.LinkType(), nil
}
```

**Step 3: `capture/main.go`**

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
	iface  := flag.String("i", "", "interface réseau (Linux)")
	filter := flag.String("f", "true", "filtre WinDivert (Windows) / ignoré sur Linux")
	count  := flag.Int("n", 0, "nombre de paquets à capturer (0 = infini)")
	flag.Parse()

	src, decoder, err := newSource(*iface, *filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ps := gopacket.NewPacketSource(src, decoder)
	captured := 0
	for pkt := range ps.Packets() {
		fmt.Println(pkt)
		captured++
		if *count > 0 && captured >= *count { break }
	}
	log.Printf("captured %d packets", captured)
}
```

**Step 4: Mettre à jour go.work**

Ajouter les replace directives dans `go.work` pour les dépendances locales :
```
go 1.22

use (
    ./windivert
    ./afpacket
    ./capture
)
```

Et dans `capture/go.mod` :
```
require (
    pkt/windivert v0.0.0
    pkt/afpacket  v0.0.0
    github.com/google/gopacket v1.1.19
)
```

**Step 5: Vérifier la compilation**

```bash
# Linux
GOOS=linux go build ./capture/...

# Windows (depuis Windows ou cross-compile)
GOOS=windows go build ./capture/...
```

**Step 6: Commit final**
```bash
git add capture/source_linux.go capture/source_windows.go capture/main.go capture/go.mod
git commit -m "feat(capture): cross-platform capture program"
```

---

## Checklist finale

- [ ] `go work sync` sans erreur
- [ ] `GOOS=linux go build ./...` passe
- [ ] `GOOS=windows go build ./...` passe
- [ ] `GOOS=windows go test ./windivert/filter/...` passe
- [ ] `GOOS=linux go test ./afpacket/...` passe (ou skip si pas sur Linux)
- [ ] IDs des champs WinDivert vérifiés contre le source C
- [ ] IOCTL codes vérifiés contre `windivert_device.h`
- [ ] Structure `WINDIVERT_ADDRESS` vérifiée contre `windivert.h`
- [ ] `WINDIVERT_FILTER_OBJECT` layout vérifié contre `windivert_device.h`
- [ ] Jump patching AND/OR dans `compiler.go` complété
