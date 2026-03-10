# drop

**Windows only.** Silently discards packets matching a WinDivert filter. Matched packets are intercepted by the kernel and never forwarded — `Send()` is never called.

## Flags

| Flag | Description |
|------|-------------|
| `-f <filter>` | **Required.** WinDivert filter expression (e.g. `tcp.DstPort == 443`) |
| `-v` | Verbose: log each dropped packet (src IP, dst IP, protocol, size) |

## Examples

**Drop all TCP traffic to port 443:**

```
drop.exe -f "tcp.DstPort == 443"
```

**Drop all packets from a specific IP:**

```
drop.exe -f "ip.SrcAddr == 192.168.1.100"
```

**Drop all outbound UDP traffic, with logging:**

```
drop.exe -f "outbound and udp" -v
```

**Drop all traffic on a specific interface (by index):**

```
drop.exe -f "ifIdx == 3"
```

To find interface indexes on Windows:

```powershell
Get-NetAdapter | Select Name, InterfaceIndex, Status
```

## How it works

The handle is opened without `FlagSniff`, so matched packets are held by the WinDivert kernel driver. Because the program never calls `Send()`, the packets are discarded when the loop moves on. This is the standard WinDivert drop pattern.

Press `Ctrl+C` to stop. A summary of the total number of dropped packets is printed on exit.

## Privileges

Requires administrator privileges on Windows.

## Filter syntax

See the [WinDivert filter language reference](https://reqrypt.org/windivert-doc.html#filter_language) and the filter syntax section in the [workspace README](../../../../README.md).
