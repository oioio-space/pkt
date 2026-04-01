# pkt

Go multi-module workspace for cross-platform packet capture. Provides passive sniffing, active packet interception, injection, and modification on Windows (via WinDivert) and passive sniffing on Linux (via AF_PACKET). All sources implement `gopacket.PacketDataSource`.

Status: working, tested on Windows 11 and Linux (amd64).

## Installation

Each module is independently versioned. Install only what you need:

```sh
# Cross-platform capture API (recommended starting point)
go get github.com/oioio-space/pkt/capture@latest

# WinDivert — Windows packet interception (included via capture on Windows)
go get github.com/oioio-space/pkt/windivert@latest

# AF_PACKET — Linux raw socket capture (included via capture on Linux)
go get github.com/oioio-space/pkt/afpacket@latest

# BPF — compile pcap-filter expressions for AF_PACKET sockets
go get github.com/oioio-space/pkt/bpf@latest
```

> `examples/` contains runnable demos and is not a published module.

## Features

- Cross-platform capture API (`pkt/capture`) with a single `Open(iface, filter)` call
- Windows: WinDivert 2.2.2 — intercept, drop, modify, and re-inject packets at the network layer
- Linux: AF_PACKET with `SO_TIMESTAMP` — passive sniffing with kernel BPF filters
- `gopacket`-compatible: all sources implement `gopacket.PacketDataSource`
- Embedded WinDivert64.sys 2.2.2 — no separate driver installation needed by default
- BPF kernel filters on Linux, WinDivert filter expressions on Windows
- pcap export compatible with Wireshark

## Why not libpcap?

libpcap (and its Go wrapper `gopacket/pcap`) is the most common packet capture library. It works on both Windows (via Npcap) and Linux and is well-supported. **If passive sniffing is all you need, libpcap is a perfectly fine choice.**

This project exists for use cases where libpcap falls short:

| Capability | libpcap / Npcap | AF_PACKET (Linux) | WinDivert (Windows) |
|---|---|---|---|
| Read packets | Yes | Yes | Yes |
| **Drop packets in transit** | **No** | **No** | **Yes** |
| **Modify packets in flight** | **No** | **No** | **Yes** |
| **True re-injection (same packet)** | **No** | **No** | **Yes** |
| Send independent raw packets | Yes (`pcap_inject`) | Yes (`sendto`) | Yes |
| Capture layer | **L2 — Ethernet frames** | **L2 — Ethernet frames** | **L3 — IP packets** |
| See non-IP traffic (ARP, LLDP…) | Yes | Yes | No |
| See MAC addresses | Yes | Yes | No |
| Kernel-level filtering | Yes (BPF) | Yes (BPF) | Yes (WinDivert filter) |
| CGo dependency | **Yes** | No (this lib) | **No** — pure Go |
| Windows driver | Requires Npcap/WinPcap installed | — | **Embedded**, extracted at runtime |
| Cross-compile (`CGO_ENABLED=0`) | No | **Yes** | **Yes** |

### Copy vs interception

libpcap and AF_PACKET deliver a **copy** of each packet — the original flows through the network stack untouched. `pcap_inject()` and AF_PACKET `sendto()` can send *independent* raw packets, but the original packet is never held or modified.

WinDivert **intercepts** packets at the Windows Filtering Platform (WFP): the packet is **held** until your code calls `h.Send()` to re-inject it (optionally modified), or drops it by not calling `Send`. This is a fundamentally different model that enables:

- **Firewalls** — drop packets matching a filter
- **Traffic shapers / proxies** — hold, rewrite, and re-inject
- **Protocol fuzzing** — corrupt fields in-flight for testing
- **Transparent tunnels** — capture, encrypt, forward, re-inject

### Layer differences: L2 vs L3

libpcap and AF_PACKET operate at **Layer 2** — they deliver raw Ethernet frames, including MAC addresses, VLAN tags, and non-IP protocols (ARP, LLDP, etc.).

WinDivert at `LayerNetwork` operates at **Layer 3** — it delivers IP packets with no Ethernet header. MAC addresses and ARP are not visible. If you need L2 visibility on Windows, libpcap/Npcap is the right tool.

### Position in the Windows network stack

On Windows, both Npcap and WinDivert hook into the **Windows Filtering Platform (WFP)**, but at different levels:

```
 Application
     │
 [ WinSock / TCP/IP stack ]
     │
 ┌───┴────────────────────────────────┐
 │  Windows Filtering Platform (WFP)  │
 │                                    │
 │  ← WinDivert callout driver        │  intercepts here — packet is held
 │    (FWPM_LAYER_OUTBOUND_IPPACKET…) │
 └───┬────────────────────────────────┘
     │
 [ NDIS — Network Driver Interface ]
     │
 ┌───┴──────────────────────────┐
 │  Npcap NDIS filter driver    │  copies here — original flows through
 └───┬──────────────────────────┘
     │
 Network interface card (NIC)
```

Npcap sits **below** WFP at the NDIS layer — it receives a copy of the raw Ethernet frame after the WFP decision has already been made. It cannot influence routing or firewall decisions.

WinDivert registers a **WFP callout** — it runs *inside* the firewall decision pipeline. The kernel waits for `h.Send()` before forwarding the packet, which is why drop and modify are possible.

### No CGo, no external dependency

libpcap requires CGo and a system library (`libpcap.so` on Linux, `Npcap.dll` on Windows). This complicates cross-compilation, Docker images, and bare Windows deployments.

`pkt` is `CGO_ENABLED=0` throughout. The WinDivert64.sys driver is embedded in the binary and extracted at runtime — no separate installation step.

### When to use what

| Situation | Recommendation |
|---|---|
| Sniff traffic on Linux, need Ethernet/MAC/ARP | `gopacket/pcap` or `pkt/afpacket` |
| Sniff IP traffic on Linux, no CGo | `pkt/afpacket` |
| Sniff traffic on Windows | `pkt/capture` or `gopacket/pcap` |
| Need MAC addresses / ARP on Windows | `gopacket/pcap` (Npcap, L2) |
| **Drop / block packets on Windows** | **`pkt/windivert`** — only real option |
| **Modify packets in flight on Windows** | **`pkt/windivert`** — only real option |
| Zero CGo, cross-compile from Linux to Windows | **`pkt`** |
| Already using libpcap everywhere | Stick with `gopacket/pcap` |

## Finding network interfaces

**Windows (PowerShell):**

```powershell
Get-NetAdapter | Select Name, InterfaceIndex, Status
# or
ipconfig
```

**Windows (cmd):**

```cmd
netsh interface show interface
```

**Linux:**

```bash
ip link show
# or
ls /sys/class/net/
```

## Usage examples

### 1. Sniffer — cross-platform (`pkt/capture`)

```go
import "github.com/oioio-space/pkt/capture"

// Linux — interface required
src, err := capture.Open("eth0", "tcp port 443")

// Windows — interface ignored, WinDivert filter syntax
// src, err := capture.Open("", "tcp.DstPort == 443")

if err != nil {
    log.Fatal(err)
}
defer src.Close()

ps := gopacket.NewPacketSource(src, src.LinkType())
for pkt := range ps.Packets() {
    fmt.Println(pkt)
}
```

### 2. Sniffer — WinDivert directly (`pkt/windivert`)

```go
import "github.com/oioio-space/pkt/windivert"

h, err := windivert.OpenSniff("tcp.DstPort == 443", windivert.LayerNetwork)
// equivalent: windivert.Open("tcp.DstPort == 443", windivert.LayerNetwork, windivert.WithFlags(windivert.FlagSniff))
if err != nil {
    log.Fatal(err)
}
defer h.Close()

ps := gopacket.NewPacketSource(h, h.LinkType())
for pkt := range ps.Packets() {
    fmt.Println(pkt)
}
```

### 3. Drop packets (Windows)

```go
h, err := windivert.Open("tcp.DstPort == 443", windivert.LayerNetwork)
if err != nil {
    log.Fatal(err)
}
defer h.Close()

ps := gopacket.NewPacketSource(h, h.LinkType())
for range ps.Packets() {
    // Don't call h.Send() — kernel discards the packet
}
```

### 4. Re-inject / forward a packet (Windows)

```go
h, err := windivert.Open("tcp", windivert.LayerNetwork)
if err != nil {
    log.Fatal(err)
}
defer h.Close()

ps := gopacket.NewPacketSource(h, h.LinkType())
for pkt := range ps.Packets() {
    addr := windivert.AddressFromPacket(pkt)
    if addr == nil {
        continue
    }
    // optionally modify pkt.Data() here
    _ = h.Send(pkt.Data(), addr)
}
```

### 5. Write a pcap file

```go
f, _ := os.Create("out.pcap")
bw := bufio.NewWriterSize(f, 1<<20)
defer bw.Flush()
defer f.Close()

w := pcapgo.NewWriter(bw)
_ = w.WriteFileHeader(65535, layers.LinkTypeIPv4)

src, _ := capture.Open("", "tcp") // Windows — iface ignored
defer src.Close()

ps := gopacket.NewPacketSource(src, src.LinkType())
for pkt := range ps.Packets() {
    ci := pkt.Metadata().CaptureInfo
    _ = w.WritePacket(ci, pkt.Data())
}
```

### 6. Install WinDivert driver persistently (Windows, admin)

```go
import (
    "github.com/oioio-space/pkt/windivert"
    "github.com/oioio-space/pkt/windivert/driver"
)

// Install driver permanently (SERVICE_AUTO_START, stable path in System32\drivers\)
err := windivert.InstallDriver(driver.WithPersistent())
```

After a persistent install, subsequent calls to `windivert.Open` skip the SCM install step and open the device directly.

### 7. Get the embedded driver version

```go
fmt.Println(windivert.DriverVersion) // "2.2.2"
```

## WinDivert filter syntax

WinDivert filters are C-like boolean expressions evaluated on packet fields:

```
tcp                             # all TCP packets
tcp.DstPort == 443              # TCP to port 443
ip.SrcAddr == 192.168.1.1       # from specific IP
tcp and not tcp.DstPort == 80   # TCP except port 80
ip.TTL < 5                      # low TTL
outbound and tcp                # outbound TCP only
not loopback                    # exclude loopback
true                            # all packets
```

Common fields:

| Field | Description |
|-------|-------------|
| `tcp`, `udp`, `icmp`, `ip`, `ipv6` | Protocol predicates |
| `tcp.SrcPort`, `tcp.DstPort` | TCP port numbers |
| `udp.SrcPort`, `udp.DstPort` | UDP port numbers |
| `ip.SrcAddr`, `ip.DstAddr` | IPv4 addresses |
| `ipv6.SrcAddr`, `ipv6.DstAddr` | IPv6 addresses |
| `ip.TTL`, `ip.Protocol` | IP header fields |
| `tcp.Syn`, `tcp.Ack`, `tcp.Fin`, `tcp.Rst` | TCP flags |
| `outbound`, `inbound` | Direction |
| `loopback` | Loopback interface |
| `ifIdx` | Interface index |

Full reference: https://reqrypt.org/windivert-doc.html#filter_language

## Linux BPF filter syntax (pcap-filter)

```
tcp port 443            # TCP port 443 (src or dst)
tcp dst port 80         # TCP destination port 80
host 192.168.1.1        # traffic to/from host
src host 10.0.0.1       # traffic from host
net 192.168.1.0/24      # subnet
tcp and not port 22     # TCP except SSH
udp port 53             # DNS
```

Full reference: `man pcap-filter`

## Building

**Linux:**

```bash
make linux       # build Linux capture binary → dist/capture-linux-amd64
make check       # build + vet
make test        # run unit tests (no root required)
make setcap      # grant CAP_NET_RAW to the Linux binary (requires sudo)
```

**Windows (PowerShell):**

```powershell
.\build.ps1                   # build all (Linux + Windows binaries)
.\build.ps1 -Target windows   # Windows binaries only
.\build.ps1 -Target linux     # Linux binary only (cross-compile)
.\build.ps1 -Target check     # build + vet
.\build.ps1 -Target test      # run unit tests
.\build.ps1 -Target clean     # remove dist/
```

Build outputs go to `dist/`. All binaries are statically linked (`CGO_ENABLED=0`).

## Module structure

```
pkt/
├── afpacket/      # Linux raw socket capture (AF_PACKET + SO_TIMESTAMP + BPF)
├── bpf/           # BPF filter compiler (used by afpacket on Linux)
├── capture/       # Cross-platform unified capture API (wraps windivert/afpacket)
├── windivert/     # Windows kernel driver bindings (WinDivert 2.2.2)
│   ├── assets/    # Embedded WinDivert64.sys
│   ├── driver/    # SCM driver installer (temporary + persistent modes)
│   └── filter/    # WinDivert filter expression compiler (bytecode)
└── examples/
    └── cmd/
        ├── capture/         # Cross-platform sniffer + pcap writer
        ├── drop/            # Windows: drop packets matching a filter
        ├── filter/          # Windows: firewall (blacklist / whitelist)
        └── modify-payload/  # Windows: rewrite TCP payload in-flight
```

See each example's README for flags and usage:

- [`examples/cmd/capture`](examples/cmd/capture/README.md) — cross-platform sniffer, pcap export
- [`examples/cmd/drop`](examples/cmd/drop/README.md) — Windows packet dropper
- [`examples/cmd/filter`](examples/cmd/filter/README.md) — Windows firewall (blacklist/whitelist)
- [`examples/cmd/modify-payload`](examples/cmd/modify-payload/README.md) — Windows TCP payload modifier
