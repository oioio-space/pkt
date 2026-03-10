# modify-payload

**Windows only.** Intercepts TCP packets matching a WinDivert filter and replaces a byte sequence in the TCP payload before re-injecting the packet. IP and TCP checksums are recomputed and lengths are fixed after the replacement.

## Flags

| Flag | Description |
|------|-------------|
| `-f <filter>` | WinDivert filter expression (default: `tcp`) |
| `-find <text>` | **Required.** Text to search for in the TCP payload |
| `-replace <text>` | Replacement text (default: empty string — deletes occurrences) |

## Examples

**Replace `HTTP/1.1` with `HTTP/1.0` in all TCP traffic:**

```
modify-payload.exe -find "HTTP/1.1" -replace "HTTP/1.0"
```

**Replace a specific hostname in HTTP Host headers:**

```
modify-payload.exe -f "tcp.DstPort == 80" -find "example.com" -replace "replaced.com"
```

**Strip a specific string (replace with nothing):**

```
modify-payload.exe -f "tcp.DstPort == 80" -find "X-Debug: true\r\n" -replace ""
```

## How it works

1. Packets matching `-f` are intercepted (kernel holds them).
2. If the TCP payload contains the search string, `bytes.ReplaceAll` is used to replace all occurrences.
3. The packet is re-serialized with `FixLengths: true` and `ComputeChecksums: true` — IP total length, TCP checksum, and IP checksum are all updated.
4. The modified packet is sent back via `h.Send()`.
5. Packets that do not contain the search string are forwarded unchanged.

## Important: length changes and TCP sequence numbers

When the replacement string is a different length than the search string, the IP packet length changes. While `FixLengths` and `ComputeChecksums` keep the immediate packet valid, **TCP sequence numbers are not adjusted**. The remote host tracks byte offsets using sequence numbers, so changing payload length will cause the TCP stream to desynchronize. This works reliably only when `-find` and `-replace` have the same byte length, or when intercepting single-packet exchanges (e.g. short HTTP/1.0 requests) where stream state does not carry over.

Press `Ctrl+C` to stop. A summary of modified vs. forwarded packet counts is printed on exit.

## Privileges

Requires administrator privileges on Windows.

## Filter syntax

See the [WinDivert filter language reference](https://reqrypt.org/windivert-doc.html#filter_language) and the filter syntax section in the [workspace README](../../../../README.md).
