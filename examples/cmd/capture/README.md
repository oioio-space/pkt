# capture

Cross-platform packet capture with optional pcap export. Uses WinDivert on Windows and AF_PACKET on Linux.

## Flags

| Flag | Description |
|------|-------------|
| `-i <iface>` | Network interface (required on Linux, e.g. `eth0`; ignored on Windows) |
| `-f <filter>` | Capture filter (WinDivert syntax on Windows, pcap-filter on Linux; empty = all traffic) |
| `-n <count>` | Stop after N packets (default: 0 = unlimited) |
| `-w <file>` | Write captured packets to a pcap file (e.g. `out.pcap`) |
| `-install-persistent` | **Windows only**: install WinDivert permanently with user-mode access, then exit (requires admin) |

## Examples

**Capture all traffic and print to stdout:**

```
# Windows
capture.exe

# Linux
capture -i eth0
```

**Capture TCP port 443 and save to a pcap file:**

```
# Windows
capture.exe -f "tcp.DstPort == 443" -w out.pcap

# Linux
capture -i eth0 -f "tcp port 443" -w out.pcap
```

**Capture the first 100 packets:**

```
# Windows
capture.exe -n 100

# Linux
capture -i eth0 -n 100
```

**Install WinDivert driver persistently (Windows, run once as admin):**

```
capture.exe -install-persistent
```

This installs WinDivert as a permanent Windows service (`SERVICE_AUTO_START`) and grants Authenticated Users access to the device — subsequent captures do not require admin.

## Output

Without `-w`, packets are printed to stdout in gopacket's default text format. With `-w`, packets are written as a standard pcap file (linktype IPv4 on Windows, Ethernet on Linux) readable by Wireshark and other tools.

## Privileges

- **Windows**: administrator required (unless `-install-persistent` was already run)
- **Linux**: root or `CAP_NET_RAW` required

To grant `CAP_NET_RAW` to the Linux binary without running as root:

```bash
sudo setcap cap_net_raw+eip ./capture
./capture -i eth0
```

## Filter syntax

- **Windows**: WinDivert filter expression — see [WinDivert filter language](https://reqrypt.org/windivert-doc.html#filter_language)
- **Linux**: pcap-filter expression — see `man pcap-filter`
