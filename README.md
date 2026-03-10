# pkt

Go multi-module workspace for cross-platform packet capture. Provides passive sniffing, active packet interception, injection, and modification on Windows (via WinDivert) and passive sniffing on Linux (via AF_PACKET). All sources implement `gopacket.PacketDataSource`.

Status: working, tested on Windows 11 and Linux (amd64).

## Features

- Cross-platform capture API (`pkt/capture`) with a single `Open(iface, filter)` call
- Windows: WinDivert 2.2.2 — intercept, drop, modify, and re-inject packets at the network layer
- Linux: AF_PACKET with `SO_TIMESTAMP` — passive sniffing with kernel BPF filters
- `gopacket`-compatible: all sources implement `gopacket.PacketDataSource`
- Embedded WinDivert64.sys 2.2.2 — no separate driver installation needed by default
- BPF kernel filters on Linux, WinDivert filter expressions on Windows
- pcap export compatible with Wireshark

## WinDivert vs AF_PACKET vs libpcap

| Feature | WinDivert (Windows) | AF_PACKET (Linux) | libpcap |
|---------|--------------------|--------------------|---------|
| Platform | Windows only | Linux only | Cross-platform |
| Packet interception | Yes (drop/modify/reinject) | No (read-only) | No (read-only) |
| Raw injection | Yes | Yes (sendto) | No |
| Kernel-level filtering | Yes (WinDivert filter) | Yes (BPF) | Yes (BPF) |
| Ethernet access | No (IP layer only) | Yes | Yes |
| Promiscuous mode | No (WFP hooks, all machine traffic) | Yes | Yes |
| Admin required | Yes | root or CAP_NET_RAW | root or special group |

WinDivert hooks into the Windows Filtering Platform (WFP) and sees all traffic on the machine without promiscuous mode. AF_PACKET gives raw socket access to a single interface. libpcap is not used in this workspace.

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
import "pkt/capture"

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
import "pkt/windivert"

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

src, _ := capture.Open("", "tcp") // Windows
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
    "pkt/windivert"
    "pkt/windivert/driver"
)

// Permanent install + allow non-admin users to capture
err := windivert.InstallDriver(
    driver.WithPersistent(), // SERVICE_AUTO_START, stable path in System32\drivers\
    driver.WithUserAccess(), // DACL: Authenticated Users can open the device
)
```

After this, non-admin users can call `windivert.Open` without elevation.

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
