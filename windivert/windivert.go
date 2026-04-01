//go:build windows

package windivert

import (
	"fmt"

	"golang.org/x/sys/windows"
	"pkt/windivert/assets"
	"pkt/windivert/driver"
	"pkt/windivert/filter"
)

type options struct {
	SnapLen  int
	Priority int16
	Flags    uint64
}

func defaultOptions() options {
	return options{SnapLen: 65535, Priority: PriorityDefault}
}

// Option configures a Handle.
type Option func(*options)

// WithSnapLen sets the maximum packet size to capture.
func WithSnapLen(n int) Option { return func(o *options) { o.SnapLen = n } }

// WithPriority sets the WinDivert priority (-30000..30000).
func WithPriority(p int16) Option { return func(o *options) { o.Priority = p } }

// WithFlags sets WinDivert flags (FlagSniff, FlagDrop, …).
func WithFlags(f uint64) Option { return func(o *options) { o.Flags = f } }

// Open installs the WinDivert driver if needed, compiles the filter, and opens a Handle.
// Requires administrator privileges (WinDivert enforces this via its device DACL).
//
// If the driver is already running (e.g. after a persistent install), Open skips
// the SCM install step and opens the device directly.
//
// filterStr is a WinDivert 2.x filter expression (e.g. "tcp", "ip and tcp.DstPort == 443").
// layer is the capture layer (typically LayerNetwork).
func Open(filterStr string, layer Layer, opts ...Option) (*Handle, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	// Try opening the device first; install the driver only if it is not yet running.
	win, openErr := driver.OpenDevice()
	if openErr != nil {
		if err := driver.Install(assets.Sys64); err != nil {
			return nil, fmt.Errorf("install driver: %w", err)
		}
		win, openErr = driver.OpenDevice()
	}
	if openErr != nil {
		return nil, fmt.Errorf("open device: %w", openErr)
	}

	prog, err := filter.Compile(filterStr)
	if err != nil {
		_ = windows.CloseHandle(win)
		return nil, fmt.Errorf("compile filter: %w", err)
	}

	h := &Handle{win: win, layer: layer, opts: o}
	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(win)
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}
	h.event = ev
	h.recvBuf = make([]byte, o.SnapLen)
	if err := h.initialize(prog, o.Priority, o.Flags); err != nil {
		h.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	return h, nil
}

// OpenSniff ouvre un handle WinDivert en mode sniff passif (FlagSniff).
// Les paquets ne sont pas interceptés — ils continuent de circuler normalement.
func OpenSniff(filterStr string, layer Layer, opts ...Option) (*Handle, error) {
	opts = append([]Option{WithFlags(FlagSniff)}, opts...)
	return Open(filterStr, layer, opts...)
}

// InstallDriver installs the WinDivert driver via SCM with the given options.
// Without options: temporary behavior (compatible with Open).
// With driver.WithPersistent(): permanent installation (survives reboots).
// With driver.WithUserAccess() or driver.WithACL(sddl): allows access without admin rights.
//
// Example — permanent installation for all authenticated users:
//
//	err := windivert.InstallDriver(driver.WithPersistent(), driver.WithUserAccess())
func InstallDriver(opts ...driver.InstallOption) error {
	return driver.Install(assets.Sys64, opts...)
}
