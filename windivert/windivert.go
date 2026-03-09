//go:build windows

package windivert

import (
	"fmt"

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

// Open installs the WinDivert driver, compiles the filter, and opens a Handle.
// Requires administrator privileges.
//
// filterStr is a WinDivert 2.x filter expression (e.g. "tcp", "ip and tcp.DstPort == 443").
// layer is the capture layer (typically LayerNetwork).
func Open(filterStr string, layer Layer, opts ...Option) (*Handle, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	if err := driver.Install(assets.Sys64); err != nil {
		return nil, fmt.Errorf("install driver: %w", err)
	}

	prog, err := filter.Compile(filterStr)
	if err != nil {
		return nil, fmt.Errorf("compile filter: %w", err)
	}

	win, err := driver.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("open device: %w", err)
	}

	h := &Handle{win: win, layer: layer, opts: o}
	if err := h.initialize(prog, o.Priority, o.Flags); err != nil {
		h.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}
	return h, nil
}
