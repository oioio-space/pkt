# Performance & Correctness Improvements Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce per-packet allocations in WinDivert and afpacket, expose `*Address` via gopacket's `AncillaryData`, use kernel timestamps on Linux, and clean up build artifacts from git.

**Architecture:** Six independent improvements touching `windivert/handle.go`, `windivert/source.go`, `afpacket/source.go`, `afpacket/socket.go`, `examples/cmd/capture/main.go`, and `.gitignore`. Each task is self-contained and safe to implement in order.

**Tech Stack:** Go 1.26, WinDivert 2.2, afpacket (AF_PACKET + SO_TIMESTAMP), gopacket

---

## Context

### windivert/handle.go (current state)

```go
type Handle struct {
    win   windows.Handle
    layer Layer
    opts  options
}

func (h *Handle) Recv(buf []byte) (int, *Address, time.Time, error) {
    addr := new(Address)                         // allocation per call
    ov := new(windows.Overlapped)               // allocation per call
    ev, err := windows.CreateEvent(...)         // 2 syscalls per call (Create+Close)
    defer windows.CloseHandle(ev)
    ov.HEvent = ev
    ...
}
```

### windivert/source.go (current state)

```go
func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
    buf := make([]byte, h.opts.SnapLen)          // allocation per call
    n, _, ts, err := h.Recv(buf)
    ...
    return buf[:n], gopacket.CaptureInfo{...}, nil
    // *Address is discarded — not in AncillaryData
}
```

### afpacket/source.go (current state)

```go
func readPacket(h *Handle) ([]byte, gopacket.CaptureInfo, error) {
    buf := make([]byte, h.opts.SnapLen)          // allocation per call
    n, _, err := unix.Recvfrom(h.fd, buf, 0)   // ignores kernel timestamp
    ...
    Timestamp: time.Now(),                        // userspace timestamp (less accurate)
}
```

### examples/cmd/capture/main.go (current state)

```go
pcapWriter = pcapgo.NewWriter(f)                 // no bufio wrapper — write syscall per packet
```

---

### Task 1: .gitignore + untrack dist/ binaries

**Files:**
- Create: `.gitignore`
- Run: `git rm --cached` for dist/ contents

- [ ] **Step 1: Create .gitignore**

```
# Build artifacts
dist/
*.exe
capture
filter

# Go workspace temp files
go.work.sum
```

- [ ] **Step 2: Untrack dist/ binaries already committed**

```bash
git rm --cached -r dist/
```

- [ ] **Step 3: Verify no build artifacts remain tracked**

Run: `git status`
Expected: dist/ files show as "Changes to be staged" (removed from index)

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: add .gitignore, untrack dist/ build artifacts"
```

---

### Task 2: Reuse Event/Overlapped in windivert/Handle

**Files:**
- Modify: `windivert/handle.go`
- Modify: `windivert/windivert.go` (Open() must init + close event)

The goal: create the Windows event handle once per Handle, store it in the struct, reuse across every Recv() call. Reset the Overlapped struct fields before each use.

- [ ] **Step 1: Add fields to Handle struct**

In `windivert/handle.go`, modify the Handle struct:

```go
type Handle struct {
    win   windows.Handle
    layer Layer
    opts  options
    event windows.Handle   // reused across Recv() calls
    ov    windows.Overlapped // reused, zeroed before each Recv()
}
```

- [ ] **Step 2: Initialize event in Open()**

In `windivert/windivert.go`, after `h := &Handle{win: win, layer: layer, opts: o}`:

```go
ev, err := windows.CreateEvent(nil, 0, 0, nil)
if err != nil {
    _ = windows.CloseHandle(win)
    return nil, fmt.Errorf("CreateEvent: %w", err)
}
h.event = ev
```

- [ ] **Step 3: Close event in Close()**

In `windivert/handle.go`, modify Close():

```go
func (h *Handle) Close() error {
    h.Shutdown()
    windows.CloseHandle(h.event)
    return windows.CloseHandle(h.win)
}
```

- [ ] **Step 4: Reuse event/overlapped in Recv()**

Replace the per-call CreateEvent/CloseHandle with reuse of `h.event` and `h.ov`:

```go
func (h *Handle) Recv(buf []byte) (int, *Address, time.Time, error) {
    addr := new(Address)
    addrLen := uint32(unsafe.Sizeof(*addr))

    var ioRecv [16]byte
    binary.LittleEndian.PutUint64(ioRecv[0:], uint64(uintptr(unsafe.Pointer(addr))))
    binary.LittleEndian.PutUint64(ioRecv[8:], uint64(uintptr(unsafe.Pointer(&addrLen))))

    var returned uint32
    h.ov = windows.Overlapped{HEvent: h.event} // reset + set event

    err := windows.DeviceIoControl(
        h.win, ioctlCodeRecv,
        &ioRecv[0], uint32(len(ioRecv)),
        &buf[0], uint32(len(buf)),
        &returned, &h.ov,
    )
    if err == windows.ERROR_IO_PENDING {
        if _, err = windows.WaitForSingleObject(h.event, windows.INFINITE); err != nil {
            return 0, nil, time.Time{}, fmt.Errorf("WaitForSingleObject: %w", err)
        }
        err = windows.GetOverlappedResult(h.win, &h.ov, &returned, false)
    }
    if err != nil {
        return 0, nil, time.Time{}, fmt.Errorf("Recv: %w", err)
    }

    ts := time.Now()
    if addr.Timestamp != 0 {
        const windowsToUnixEpoch = 116444736000000000
        ts = time.Unix(0, (addr.Timestamp-windowsToUnixEpoch)*100)
    }
    return int(returned), addr, ts, nil
}
```

- [ ] **Step 5: Build to verify no compile errors (Windows only)**

```bash
GOOS=windows go build ./windivert/...
```
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add windivert/handle.go windivert/windivert.go
git commit -m "perf(windivert): reuse Event/Overlapped across Recv() calls"
```

---

### Task 3: Buffer reuse + AncillaryData in windivert/source.go

**Files:**
- Modify: `windivert/handle.go` (add recvBuf field)
- Modify: `windivert/windivert.go` (init recvBuf in Open())
- Modify: `windivert/source.go` (reuse buf + embed *Address in AncillaryData + add AddressFromPacket)

**Important:** `ReadPacketData` must return a *copy* of the packet bytes, not a slice into the shared buffer — gopacket may hold the slice after the next read.

- [ ] **Step 1: Add recvBuf field to Handle**

In `windivert/handle.go`:

```go
type Handle struct {
    win     windows.Handle
    layer   Layer
    opts    options
    event   windows.Handle
    ov      windows.Overlapped
    recvBuf []byte
}
```

- [ ] **Step 2: Initialize recvBuf in Open()**

In `windivert/windivert.go`, after creating the event:

```go
h.recvBuf = make([]byte, o.SnapLen)
```

- [ ] **Step 3: Update ReadPacketData to reuse buffer and embed *Address**

Replace `windivert/source.go`:

```go
//go:build windows

package windivert

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

// ReadPacketData implements gopacket.PacketDataSource.
// The returned slice is a copy — safe to hold across calls.
// The *Address is embedded in CaptureInfo.AncillaryData[0]; use AddressFromPacket to retrieve it.
func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
    n, addr, ts, err := h.Recv(h.recvBuf)
    if err != nil {
        return nil, gopacket.CaptureInfo{}, err
    }
    pktCopy := make([]byte, n)
    copy(pktCopy, h.recvBuf[:n])
    return pktCopy, gopacket.CaptureInfo{
        Timestamp:     ts,
        CaptureLength: n,
        Length:        n,
        AncillaryData: []interface{}{addr},
    }, nil
}

// AddressFromPacket extracts the WinDivert *Address from a gopacket.Packet.
// Returns nil if the address is not present (non-WinDivert source).
func AddressFromPacket(pkt gopacket.Packet) *Address {
    for _, v := range pkt.Metadata().CaptureInfo.AncillaryData {
        if addr, ok := v.(*Address); ok {
            return addr
        }
    }
    return nil
}

// LinkType returns the gopacket decoder appropriate for the WinDivert layer.
func (h *Handle) LinkType() gopacket.Decoder {
    switch h.layer {
    case LayerNetwork, LayerNetworkForward:
        return layers.LayerTypeIPv4
    default:
        return layers.LayerTypeEthernet
    }
}
```

- [ ] **Step 4: Build to verify**

```bash
GOOS=windows go build ./windivert/...
```
Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add windivert/handle.go windivert/windivert.go windivert/source.go
git commit -m "perf(windivert): reuse recv buffer; embed *Address in AncillaryData; add AddressFromPacket"
```

---

### Task 4: Rewrite drop and modify-payload to use NewPacketSource + AddressFromPacket

**Files:**
- Modify: `examples/cmd/drop/main.go`
- Modify: `examples/cmd/modify-payload/main.go`

**drop/main.go** — use `gopacket.NewPacketSource` (no need for Address since we never Send):

```go
//go:build windows

package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "pkt/windivert"
)

func main() {
    filterExpr := flag.String("f", "", "filtre WinDivert — paquets matchant ce filtre seront droppés")
    verbose    := flag.Bool("v", false, "affiche les détails de chaque paquet droppé")
    flag.Parse()

    if *filterExpr == "" {
        fmt.Fprintln(os.Stderr, "flag -f requis (ex: -f \"tcp.DstPort == 443\")")
        os.Exit(1)
    }

    h, err := windivert.Open(*filterExpr, windivert.LayerNetwork)
    if err != nil {
        fmt.Fprintln(os.Stderr, "open:", err)
        os.Exit(1)
    }
    defer h.Close()

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()
    go func() { <-ctx.Done(); h.Shutdown() }()

    ps := gopacket.NewPacketSource(h, h.LinkType())
    dropped := 0

    log.Printf("drop actif (filtre: %q) — Ctrl+C pour arrêter", *filterExpr)

    for pkt := range ps.Packets() {
        dropped++
        if *verbose {
            if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
                ip := ipLayer.(*layers.IPv4)
                log.Printf("drop #%d : %v → %v proto=%v size=%d",
                    dropped, ip.SrcIP, ip.DstIP, ip.Protocol, len(pkt.Data()))
            } else {
                log.Printf("drop #%d : %d bytes", dropped, len(pkt.Data()))
            }
        }
        // Ne pas appeler h.Send → le noyau supprime le paquet
    }
    log.Printf("terminé — %d paquets droppés", dropped)
}
```

**modify-payload/main.go** — use `gopacket.NewPacketSource` + `windivert.AddressFromPacket`:

```go
//go:build windows

package main

import (
    "bytes"
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "pkt/windivert"
)

func main() {
    filterExpr := flag.String("f", "tcp", "filtre WinDivert (ex: \"tcp.DstPort == 80\")")
    findStr    := flag.String("find", "", "texte à remplacer dans le payload TCP")
    replaceStr := flag.String("replace", "", "texte de remplacement")
    flag.Parse()

    if *findStr == "" {
        fmt.Fprintln(os.Stderr, "flag -find requis")
        os.Exit(1)
    }

    h, err := windivert.Open(*filterExpr, windivert.LayerNetwork)
    if err != nil {
        fmt.Fprintln(os.Stderr, "open:", err)
        os.Exit(1)
    }
    defer h.Close()

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()
    go func() { <-ctx.Done(); h.Shutdown() }()

    ps := gopacket.NewPacketSource(h, h.LinkType())
    find    := []byte(*findStr)
    replace := []byte(*replaceStr)
    modified, forwarded := 0, 0

    log.Printf("interception active (filtre: %q, find: %q → replace: %q)", *filterExpr, *findStr, *replaceStr)

    for pkt := range ps.Packets() {
        addr := windivert.AddressFromPacket(pkt)
        if addr == nil {
            continue
        }

        data := pkt.Data()
        ipLayer  := pkt.Layer(layers.LayerTypeIPv4)
        tcpLayer := pkt.Layer(layers.LayerTypeTCP)

        if ipLayer != nil && tcpLayer != nil && bytes.Contains(tcpLayer.(*layers.TCP).Payload, find) {
            ip  := ipLayer.(*layers.IPv4)
            tcp := tcpLayer.(*layers.TCP)
            tcp.Payload = bytes.ReplaceAll(tcp.Payload, find, replace)
            tcp.SetNetworkLayerForChecksum(ip)

            sbuf := gopacket.NewSerializeBuffer()
            opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
            if err := gopacket.SerializeLayers(sbuf, opts, ip, tcp, gopacket.Payload(tcp.Payload)); err != nil {
                log.Printf("serialize error: %v — forwarding original", err)
            } else {
                data = sbuf.Bytes()
                modified++
                log.Printf("modifié %d bytes (TCP %v:%d → %v:%d)",
                    len(data), ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
            }
        } else {
            forwarded++
        }

        if err := h.Send(data, addr); err != nil {
            log.Printf("send error: %v", err)
        }
    }
    log.Printf("terminé — %d paquets modifiés, %d transférés", modified, forwarded)
}
```

- [ ] **Step 1: Write drop/main.go with NewPacketSource**

Write the new content to `examples/cmd/drop/main.go` using the code above.

- [ ] **Step 2: Write modify-payload/main.go with NewPacketSource + AddressFromPacket**

Write the new content to `examples/cmd/modify-payload/main.go` using the code above.

- [ ] **Step 3: Build to verify**

```bash
GOOS=windows go build ./examples/cmd/drop/...
GOOS=windows go build ./examples/cmd/modify-payload/...
```
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add examples/cmd/drop/main.go examples/cmd/modify-payload/main.go
git commit -m "refactor(examples): use NewPacketSource + AddressFromPacket in drop and modify-payload"
```

---

### Task 5: bufio.Writer for pcap + flush in capture/main.go

**Files:**
- Modify: `examples/cmd/capture/main.go`

Wrap the pcapgo.Writer with a bufio.Writer to batch write syscalls. Must flush before close.

- [ ] **Step 1: Add bufio import and wrap writer**

In `examples/cmd/capture/main.go`:

1. Add `"bufio"` to imports.
2. Replace:
   ```go
   pcapWriter = pcapgo.NewWriter(f)
   ```
   With:
   ```go
   bw := bufio.NewWriterSize(f, 1<<20) // 1 MiB buffer
   pcapWriter = pcapgo.NewWriter(bw)
   defer bw.Flush()
   ```

Note: `defer bw.Flush()` must appear BEFORE `defer f.Close()` in the code (i.e., written AFTER since defers run LIFO) — so it runs before the file is closed. Make sure the order is: first `defer f.Close()`, then `defer bw.Flush()` — so bw.Flush runs first.

Actually for correct ordering: since defers are LIFO, write `defer f.Close()` first, then `defer bw.Flush()` — flush will run before close. OR simply reorganize to call flush/close explicitly.

Cleanest approach: use explicit flush at the end and keep `defer f.Close()`.

```go
f, err := os.Create(*outFile)
if err != nil {
    fmt.Fprintln(os.Stderr, "error:", err)
    os.Exit(1)
}
defer f.Close()
bw := bufio.NewWriterSize(f, 1<<20)
defer bw.Flush()
lt := layerTypeToLinkType(decoder)
pcapWriter = pcapgo.NewWriter(bw)
```

With `defer bw.Flush()` written after `defer f.Close()`, the LIFO order ensures Flush runs first, then Close. This is correct.

- [ ] **Step 2: Build to verify**

```bash
go build ./examples/cmd/capture/...
```
(Can build on any OS since capture has platform-specific source files.)

- [ ] **Step 3: Commit**

```bash
git add examples/cmd/capture/main.go
git commit -m "perf(capture): wrap pcapgo.Writer with bufio for batched writes"
```

---

### Task 6: Kernel timestamps via SO_TIMESTAMP in afpacket

**Files:**
- Modify: `afpacket/socket.go` (enable SO_TIMESTAMP)
- Modify: `afpacket/source.go` (use Recvmsg + parse timestamp)

SO_TIMESTAMP delivers a `struct timeval` (seconds + microseconds) as a control message in the `Recvmsg` ancillary data. The socket option must be set before the first `Recvfrom`/`Recvmsg` call.

- [ ] **Step 1: Enable SO_TIMESTAMP in open()**

In `afpacket/socket.go`, after `h := &Handle{fd: fd, ifindex: ifi.Index, opts: o}`:

```go
if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1); err != nil {
    unix.Close(fd)
    return nil, fmt.Errorf("SO_TIMESTAMP: %w", err)
}
```

- [ ] **Step 2: Replace Recvfrom with Recvmsg + timestamp parsing in source.go**

Replace `afpacket/source.go`:

```go
//go:build linux

package afpacket

import (
    "time"
    "unsafe"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "golang.org/x/sys/unix"
)

func readPacket(h *Handle) ([]byte, gopacket.CaptureInfo, error) {
    buf := make([]byte, h.opts.SnapLen)
    oob := make([]byte, 64) // control message buffer (timeval fits in 32 bytes)
    n, oobn, _, _, err := unix.Recvmsg(h.fd, buf, oob, 0)
    if err != nil {
        return nil, gopacket.CaptureInfo{}, err
    }

    ts := time.Now()
    if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
        for _, msg := range msgs {
            if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SO_TIMESTAMP {
                if len(msg.Data) >= int(unsafe.Sizeof(unix.Timeval{})) {
                    tv := (*unix.Timeval)(unsafe.Pointer(&msg.Data[0]))
                    ts = time.Unix(tv.Sec, int64(tv.Usec)*1000)
                }
            }
        }
    }

    return buf[:n], gopacket.CaptureInfo{
        Timestamp:     ts,
        CaptureLength: n,
        Length:        n,
    }, nil
}

func linkType() gopacket.Decoder { return layers.LayerTypeEthernet }
```

- [ ] **Step 3: Build to verify (Linux)**

```bash
GOOS=linux go build ./afpacket/...
```
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add afpacket/socket.go afpacket/source.go
git commit -m "perf(afpacket): kernel timestamps via SO_TIMESTAMP + Recvmsg"
```

---

### Task 7: Buffer reuse in afpacket/source.go

**Files:**
- Modify: `afpacket/afpacket.go` (add recvBuf field to Handle)
- Modify: `afpacket/socket.go` (init recvBuf)
- Modify: `afpacket/source.go` (use h.recvBuf + copy for return)

**Note:** Must be done AFTER Task 6 since Task 6 rewrites source.go.

- [ ] **Step 1: Add recvBuf field to Handle**

In `afpacket/afpacket.go`:

```go
type Handle struct {
    fd      int
    ifindex int
    opts    Options
    recvBuf []byte
}
```

- [ ] **Step 2: Initialize recvBuf in open()**

In `afpacket/socket.go`, in the `open()` function, change:

```go
h := &Handle{fd: fd, ifindex: ifi.Index, opts: o}
```

To:

```go
h := &Handle{fd: fd, ifindex: ifi.Index, opts: o, recvBuf: make([]byte, o.SnapLen)}
```

- [ ] **Step 3: Use h.recvBuf in readPacket**

In `afpacket/source.go`, replace `buf := make([]byte, h.opts.SnapLen)` with `buf := h.recvBuf`, and return a copy:

```go
func readPacket(h *Handle) ([]byte, gopacket.CaptureInfo, error) {
    oob := make([]byte, 64)
    n, oobn, _, _, err := unix.Recvmsg(h.fd, h.recvBuf, oob, 0)
    if err != nil {
        return nil, gopacket.CaptureInfo{}, err
    }

    ts := time.Now()
    if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
        for _, msg := range msgs {
            if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SO_TIMESTAMP {
                if len(msg.Data) >= int(unsafe.Sizeof(unix.Timeval{})) {
                    tv := (*unix.Timeval)(unsafe.Pointer(&msg.Data[0]))
                    ts = time.Unix(tv.Sec, int64(tv.Usec)*1000)
                }
            }
        }
    }

    pktCopy := make([]byte, n)
    copy(pktCopy, h.recvBuf[:n])
    return pktCopy, gopacket.CaptureInfo{
        Timestamp:     ts,
        CaptureLength: n,
        Length:        n,
    }, nil
}
```

**Note:** The oob buffer could also be reused but 64 bytes is small enough not to matter.

- [ ] **Step 4: Build to verify**

```bash
GOOS=linux go build ./afpacket/...
```
Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add afpacket/afpacket.go afpacket/socket.go afpacket/source.go
git commit -m "perf(afpacket): reuse recv buffer across ReadPacketData calls"
```
