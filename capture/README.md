# pkt — packet capture

Cross-platform packet capture tool. Uses **WinDivert** on Windows and **AF_PACKET** on Linux.

## Usage

```
pkt [-i interface] [-f filter] [-n count]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Network interface name (Linux only — on Windows use `ifIdx` in filter) | all interfaces |
| `-f` | Capture filter (see below) | capture everything |
| `-n` | Stop after N packets (0 = run until Ctrl+C) | 0 |

Press **Ctrl+C** to stop at any time. The number of captured packets is printed on exit.

### Linux examples

```bash
sudo ./pkt-linux-amd64
sudo ./pkt-linux-amd64 -i eth0 -f "tcp port 443" -n 20
sudo ./pkt-linux-amd64 -i eth0 -f "udp port 53"
```

Or grant `cap_net_raw` once and run without sudo:
```bash
sudo make setcap
./pkt-linux-amd64 -f "tcp port 80"
```

### Windows examples (admin required)

```powershell
.\pkt-windows-amd64.exe
.\pkt-windows-amd64.exe -f "udp.DstPort == 53" -n 20
.\pkt-windows-amd64.exe -f "tcp.DstPort == 80 or tcp.DstPort == 443"
```

---

## Windows — interface and driver notes

### Filtering by interface

WinDivert captures at the IP layer across **all interfaces**. To restrict to one interface,
use the `ifIdx` field in the filter with the interface's numeric index:

```powershell
# PowerShell
Get-NetAdapter | Select-Object Name, InterfaceIndex
```

```cmd
# cmd / no PowerShell needed
route print
netsh interface ipv4 show interfaces
```

Then use the index in the filter:

```powershell
.\pkt-windows-amd64.exe -f "ifIdx == 12"
.\pkt-windows-amd64.exe -f "ifIdx == 12 and tcp.DstPort == 443"
```

The `-i` flag is not used on Windows; put the interface constraint directly in the filter.

### Driver lifecycle

The program embeds the WinDivert kernel driver (`.sys`) and installs it automatically on first run.
It follows the same lifecycle as the official WinDivert DLL:

| Event | What happens |
|-------|-------------|
| Program starts | Driver extracted to a temp dir, registered in SCM, loaded by the kernel |
| `Open()` called | SCM service marked for deletion immediately after start |
| Program running | Driver active; packets are sniffed (not dropped) |
| Ctrl+C or `-n` reached | `Shutdown()` + `Close()` called — all handles released |
| Last handle closed | Kernel unloads the driver; SCM removes the service automatically |
| Next run | Driver is re-installed transparently |

No manual uninstall step is needed. The driver does not survive across reboots or program exits.
If the driver is already loaded by another process (e.g. another instance of `pkt`), the existing
service is reused and its lifecycle is left untouched.

### Windows requirements

| Requirement | Minimum |
|-------------|---------|
| OS | Windows 10 (build 1607) or Windows Server 2016 |
| Architecture | **x64 only** — only the 64-bit driver is embedded |
| Privileges | **Administrator** (required to install a kernel driver) |

The Go 1.26 runtime sets the binding floor at Windows 10 / Server 2016.
WinDivert itself supports Vista SP1+, but the Go minimum is stricter.

---

## Filter syntax

The filter language differs between platforms.

### Windows — WinDivert filter

WinDivert uses a C-style expression language based on **packet field comparisons**.

#### Operators

| Operator | Meaning |
|----------|---------|
| `==` `!=` | equal / not equal |
| `<` `<=` `>` `>=` | numeric range |
| `and` `&&` | logical AND |
| `or` `\|\|` | logical OR |
| `not` `!` | logical NOT |

#### Key fields

| Field | Type | Description |
|-------|------|-------------|
| `ip` / `ipv6` | bool | IPv4 / IPv6 packet |
| `tcp` / `udp` / `icmp` | bool | protocol present |
| `inbound` / `outbound` | bool | traffic direction |
| `loopback` | bool | loopback interface |
| `ip.SrcAddr` / `ip.DstAddr` | IPv4 | source / destination IP |
| `ipv6.SrcAddr` / `ipv6.DstAddr` | IPv6 | source / destination IP |
| `tcp.SrcPort` / `tcp.DstPort` | uint16 | TCP ports |
| `udp.SrcPort` / `udp.DstPort` | uint16 | UDP ports |
| `ip.TTL` | uint8 | IP time-to-live |
| `tcp.Syn` / `tcp.Fin` / `tcp.Rst` | bool | TCP flags |

Numbers can be decimal (`53`) or hexadecimal (`0x35`).

#### Examples

```
true                                      # everything (default)
tcp                                       # all TCP packets
udp.DstPort == 53                         # DNS queries
tcp.DstPort == 80 or tcp.DstPort == 443  # HTTP and HTTPS
not loopback                              # exclude loopback
ip.SrcAddr == 192.168.1.1                # from specific host
tcp.DstPort >= 1024 and tcp.DstPort <= 65535  # unprivileged ports
tcp.Syn and not tcp.Ack                  # SYN (connection start)
outbound and tcp.DstPort == 443          # outbound HTTPS only
```

---

### Linux — pcap-filter (BPF)

Linux uses the **pcap-filter** language, identical to tcpdump.

#### Primitives

| Primitive | Example | Meaning |
|-----------|---------|---------|
| `host <addr>` | `host 1.2.3.4` | any packet to/from that IP |
| `src host <addr>` | `src host 1.2.3.4` | source IP |
| `dst host <addr>` | `dst host 1.2.3.4` | destination IP |
| `port <n>` | `port 80` | any packet on that TCP/UDP port |
| `src port <n>` | `src port 443` | source port |
| `dst port <n>` | `dst port 53` | destination port |
| `tcp` / `udp` / `icmp` | `udp` | protocol |
| `ip` / `ip6` | `ip6` | address family |

Combine with `and`, `or`, `not` (or `&&`, `||`, `!`).

#### Examples

```
tcp                                      # all TCP
udp port 53                             # DNS
tcp port 80 or tcp port 443             # HTTP and HTTPS
not loopback                            # exclude loopback
src host 192.168.1.1                    # from specific host
dst port 443                            # outbound HTTPS
tcp and not port 22                     # TCP excluding SSH
```

---

## WinDivert vs pcap-filter — quick comparison

| Goal | WinDivert (Windows) | pcap-filter (Linux) |
|------|---------------------|---------------------|
| All TCP | `tcp` | `tcp` |
| DNS (UDP 53) | `udp.DstPort == 53` | `udp port 53` |
| HTTP + HTTPS | `tcp.DstPort == 80 or tcp.DstPort == 443` | `tcp port 80 or tcp port 443` |
| From IP | `ip.SrcAddr == 1.2.3.4` | `src host 1.2.3.4` |
| To IP | `ip.DstAddr == 1.2.3.4` | `dst host 1.2.3.4` |
| Exclude loopback | `not loopback` | `not loopback` |
| IPv6 only | `ipv6` | `ip6` |
| Port range | `tcp.DstPort >= 8000 and tcp.DstPort <= 9000` | `tcp portrange 8000-9000` |
| SYN packets | `tcp.Syn and not tcp.Ack` | `tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0` |
| Outbound only | `outbound` | *(not available in BPF)* |

Key differences:
- **WinDivert** uses field-level C expressions (`field op value`); supports `<`, `>`, `<=`, `>=` for numeric ranges.
- **pcap-filter** uses keyword-based syntax (`src host`, `dst port`); no numeric range comparisons.
- WinDivert `outbound`/`inbound` have no pcap-filter equivalent (BPF captures at a lower level).
