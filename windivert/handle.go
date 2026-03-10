//go:build windows

package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"pkt/windivert/filter"
)

// Handle represents an open WinDivert handle.
type Handle struct {
	win     windows.Handle
	layer   Layer
	opts    options
	event   windows.Handle
	ov      windows.Overlapped
	recvBuf []byte
}

// Shutdown signals the driver to stop delivering packets and unblocks any
// pending Recv call. Safe to call before Close.
func (h *Handle) Shutdown() error {
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[0:], 3) // WINDIVERT_SHUTDOWN_BOTH = 0x3
	var returned uint32
	return windows.DeviceIoControl(
		h.win, ioctlCodeShutdown,
		&buf[0], uint32(len(buf)),
		nil, 0,
		&returned, nil,
	)
}

// Close shuts down and closes the WinDivert handle.
func (h *Handle) Close() error {
	h.Shutdown() // best-effort: unblocks any pending Recv
	_ = windows.CloseHandle(h.event)
	return windows.CloseHandle(h.win)
}

// Recv receives one packet from WinDivert. Blocks until a packet is available.
// Returns the packet data, its metadata address, and the number of bytes received.
//
// Protocol: DeviceIoControl(IOCTL_WINDIVERT_RECV, METHOD_OUT_DIRECT)
//   - lpInBuffer:  {addr_ptr uint64, addr_len_ptr uint64} (16 bytes)
//   - lpOutBuffer: packet data buffer (driver writes packet here)
func (h *Handle) Recv(buf []byte) (int, *Address, time.Time, error) {
	addr := new(Address)
	addrLen := uint32(unsafe.Sizeof(*addr))

	// Input buffer: pointers to address struct and its length variable.
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
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		if _, err = windows.WaitForSingleObject(h.event, windows.INFINITE); err != nil {
			return 0, nil, time.Time{}, fmt.Errorf("WaitForSingleObject: %w", err)
		}
		err = windows.GetOverlappedResult(h.win, &h.ov, &returned, false)
	}
	if err != nil {
		return 0, nil, time.Time{}, fmt.Errorf("recv: %w", err)
	}

	ts := time.Now()
	if addr.Timestamp != 0 {
		// Timestamp is 100-nanosecond intervals since Windows epoch (Jan 1, 1601).
		const windowsToUnixEpoch = 116444736000000000
		ts = time.Unix(0, (addr.Timestamp-windowsToUnixEpoch)*100)
	}
	return int(returned), addr, ts, nil
}

// Send injects a packet into the network.
//
// Protocol: DeviceIoControl(IOCTL_WINDIVERT_SEND, METHOD_IN_DIRECT)
//   - lpInBuffer:  {addr_ptr uint64, addr_len uint64} (16 bytes)
//   - lpOutBuffer: packet data to inject (read by driver via MdlAddress)
func (h *Handle) Send(data []byte, addr *Address) error {
	var ioSend [16]byte
	binary.LittleEndian.PutUint64(ioSend[0:], uint64(uintptr(unsafe.Pointer(addr))))
	binary.LittleEndian.PutUint64(ioSend[8:], uint64(unsafe.Sizeof(*addr)))

	var returned uint32
	return windows.DeviceIoControl(
		h.win, ioctlCodeSend,
		&ioSend[0], uint32(len(ioSend)),
		&data[0], uint32(len(data)),
		&returned, nil,
	)
}

// initialize sends the filter bytecode and starts capture.
//
// IOCTL_WINDIVERT_INITIALIZE (METHOD_OUT_DIRECT):
//   - lpInBuffer:  {layer uint32, priority uint32, flags uint64} = 16 bytes
//   - lpOutBuffer: WINDIVERT_VERSION (ignored here)
//
// IOCTL_WINDIVERT_STARTUP (METHOD_IN_DIRECT):
//   - lpInBuffer:  {flags uint64} = 8 bytes
//   - lpOutBuffer: filter bytecode (read by driver via MdlAddress)
func (h *Handle) initialize(prog []filter.FilterObject, priority int16, flags uint64) error {
	// Build INITIALIZE input: layer, priority (offset by +30000), flags.
	var ioInit [16]byte
	binary.LittleEndian.PutUint32(ioInit[0:], uint32(h.layer))
	binary.LittleEndian.PutUint32(ioInit[4:], uint32(int32(priority)+priorityMax))
	binary.LittleEndian.PutUint64(ioInit[8:], flags)

	// WINDIVERT_VERSION output buffer: send DLL magic + version, driver replies with SYS magic.
	// Layout: magic(8) + major(4) + minor(4) + bits(4) + reserved32[3](12) + reserved64[4](32) = 64 bytes.
	var versionBuf [64]byte
	binary.LittleEndian.PutUint64(versionBuf[0:], windivertMagicDLL)
	binary.LittleEndian.PutUint32(versionBuf[8:], windivertMajor)
	binary.LittleEndian.PutUint32(versionBuf[12:], windivertMinor)
	binary.LittleEndian.PutUint32(versionBuf[16:], 64) // bits = 8 * sizeof(void*) on amd64
	var returned uint32
	if err := windows.DeviceIoControl(
		h.win, ioctlCodeInitialize,
		&ioInit[0], uint32(len(ioInit)),
		&versionBuf[0], uint32(len(versionBuf)),
		&returned, nil,
	); err != nil {
		return fmt.Errorf("IOCTL_INITIALIZE: %w", err)
	}
	if binary.LittleEndian.Uint64(versionBuf[0:]) != windivertMagicSYS {
		return fmt.Errorf("IOCTL_INITIALIZE: driver version magic mismatch")
	}

	// Build STARTUP input: sizeof(WINDIVERT_IOCTL) = 16 bytes; startup.flags at offset 0.
	// filter_flags tells the driver which WFP callouts to install (inbound/outbound, IPv4/IPv6).
	var ioStartup [16]byte
	binary.LittleEndian.PutUint64(ioStartup[0:], filter.Analyze(prog, uint32(h.layer)))

	filterBytes := filter.Bytes(prog)
	if err := windows.DeviceIoControl(
		h.win, ioctlCodeStartup,
		&ioStartup[0], uint32(len(ioStartup)),
		&filterBytes[0], uint32(len(filterBytes)),
		&returned, nil,
	); err != nil {
		return fmt.Errorf("IOCTL_STARTUP: %w", err)
	}
	return nil
}
