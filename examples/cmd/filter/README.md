# filter

**Windows only.** Network firewall with blacklist or whitelist mode. Drops packets by intercepting them with WinDivert and never calling `Send()`.

## Flags

| Flag | Description |
|------|-------------|
| `-f <filter>` | **Required.** WinDivert filter expression |
| `-mode blacklist\|whitelist` | Drop mode (default: `blacklist`) |
| `-v` | Verbose: log each dropped packet |

### Modes

- **blacklist**: drops packets that match the filter. Everything else passes through untouched.
- **whitelist**: drops packets that do **not** match the filter. Only matching packets are allowed through.

In whitelist mode, the effective WinDivert filter is automatically inverted to `not (<filter>)`.

## Examples

**Block all traffic to/from an IP (blacklist):**

```
filter.exe -f "ip.SrcAddr == 10.0.0.5 or ip.DstAddr == 10.0.0.5"
```

**Allow only DNS traffic — block everything else (whitelist):**

```
filter.exe -f "udp.DstPort == 53 or udp.SrcPort == 53" -mode whitelist
```

**Block outbound HTTP and HTTPS, with logging:**

```
filter.exe -f "outbound and (tcp.DstPort == 80 or tcp.DstPort == 443)" -v
```

**Block traffic on a specific interface (by index):**

```
filter.exe -f "ifIdx == 5"
```

To find interface indexes on Windows:

```powershell
Get-NetAdapter | Select Name, InterfaceIndex, Status
```

## How it works

The handle is opened without `FlagSniff`. Matched packets are held by the WinDivert kernel driver. Because `Send()` is never called, the packets are silently discarded. In whitelist mode, the filter expression is negated so that non-matching traffic is intercepted and dropped.

Press `Ctrl+C` to stop. A summary of the total number of dropped packets is printed on exit.

## Privileges

Requires administrator privileges on Windows.

## Filter syntax

See the [WinDivert filter language reference](https://reqrypt.org/windivert-doc.html#filter_language) and the filter syntax section in the [workspace README](../../../../README.md).
