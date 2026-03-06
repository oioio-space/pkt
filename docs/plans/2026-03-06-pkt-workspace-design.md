# pkt workspace — Design

**Date:** 2026-03-06
**Scope:** Go workspace cross-platform packet capture (Windows + Linux)

## Contraintes

- Zéro CGO
- Windows : WinDivert driver protocol pur Go (embed `.sys` uniquement, pas de DLL)
- Linux : AF_PACKET SOCK_RAW via `golang.org/x/sys/unix`
- Interface gopacket (`PacketDataSource`) pour les deux

---

## Structure workspace

```
pkt/
├── go.work
├── windivert/           module pkt/windivert   [//go:build windows]
├── afpacket/            module pkt/afpacket    [//go:build linux]
├── bpf/                 module pkt/bpf         [//go:build linux]
└── capture/             module pkt/capture     [cross-platform]
```

---

## Package `pkt/windivert`

### Composants

```
filter/
  grammar.peg    grammaire PEG WinDivert 2.x (source pigeon)
  grammar.go     GÉNÉRÉ — go generate (ne pas éditer)
  compiler.go    AST pigeon → []WINDIVERT_FILTER_OBJECT (bytecode)
  fields.go      table des champs (ip.*, tcp.*, udp.*, icmp.*, ipv6.*)

driver/
  installer.go   extract WinDivert64.sys → drivers/, SCM idempotent

assets/
  WinDivert64.sys  (//go:embed, binaire)

handle.go        CreateFile + IOCTL + overlapped I/O
address.go       WINDIVERT_ADDRESS struct
source.go        gopacket.PacketDataSource
windivert.go     Open(filter, layer, priority, ...Option) (*Handle, error)
```

### Protocole driver

```
1. installer.go  : extract .sys → %SystemRoot%\System32\drivers\
                   OpenSCManager → CreateService/OpenService → StartService
2. handle.go     : CreateFile("\\\\.\\WinDivert{layer}", GENERIC_READ|WRITE, ...)
3.               : DeviceIoControl(IOCTL_INITIALIZE, compiledBytecode)
4.               : DeviceIoControl(IOCTL_STARTUP)
5.               : ReadFile(overlapped)  ← recv packets
                   WriteFile(...)        ← inject packets
```

### Filter compiler

Grammaire PEG dans `filter/grammar.peg`, générée avec **pigeon** (`go generate`).
Le fichier généré `grammar.go` est commité — pas de dépendance runtime sur pigeon.
`compiler.go` traverse l'AST pigeon et émet le bytecode `[]WINDIVERT_FILTER_OBJECT` :
```
{ field, test, arg[4], success_jump, failure_jump }
```
Référence : code source WinDivert C + constantes de `imgk/divert-go`.

### API

```go
h, err := windivert.Open("tcp.DstPort == 443",
    windivert.LayerNetwork, 0,
    windivert.WithSnapLen(65535))
defer h.Close()
// h implémente gopacket.PacketDataSource
```

---

## Package `pkt/bpf`

### Composants

```text
bpf/
  bpf.go         Compile(expr string)([]bpf.Instruction,error)
                 Attach(fd int, filter []bpf.Instruction)error
                 Detach(fd int)error
```

Parse pcap-filter style strings (`tcp port 80`, `ip`, `host x.x.x.x`) via
`packetcap/go-pcap/filter`. Attache au socket via `SO_ATTACH_FILTER`
(`unix.SetsockoptSockFprog`). Utilisé par `pkt/afpacket` via `WithFilter(expr)`.

---

## Package `pkt/afpacket`

### Composants

```
socket.go        socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) + bind
promiscuous.go   PACKET_ADD_MEMBERSHIP / REMOVE_MEMBERSHIP
source.go        ReadPacketData() via unix.Recvfrom
afpacket.go      Open(iface string, ...Option) (*Handle, error)
```

Pas de TPACKET_V3 en V1 (YAGNI). Frames Ethernet complètes (layer 2).

### API

```go
h, err := afpacket.Open("eth0",
    afpacket.WithPromiscuous(true),
    afpacket.WithFilter("tcp port 80"))  // BPF kernel-side via pkt/bpf
defer h.Close()
// h implémente gopacket.PacketDataSource
```

---

## Package `pkt/capture`

```
source_windows.go   //go:build windows  → windivert.Open
source_linux.go     //go:build linux    → afpacket.Open
main.go             flags: -i iface, -f filter
```

```go
src, decoder, err := newSource(iface, filter, opts)
ps := gopacket.NewPacketSource(src, decoder)
for pkt := range ps.Packets() { fmt.Println(pkt) }
```

---

## Dépendances

| Module        | Dépendances runtime                                          |
|---------------|--------------------------------------------------------------|
| pkt/bpf       | packetcap/go-pcap/filter, golang.org/x/net/bpf, x/sys/unix  |
| pkt/windivert | golang.org/x/sys/windows, gopacket                          |
| pkt/afpacket  | pkt/bpf, golang.org/x/sys/unix, gopacket                    |
| pkt/capture   | pkt/windivert ou pkt/afpacket, gopacket                     |

Outil build-time (non-runtime) : `github.com/mna/pigeon` (go generate, go install).
Référence non-dépendance : source C WinDivert 2.x + `imgk/divert-go` pour les constantes.
