//go:build linux

package afpacket

import "github.com/google/gopacket"

type Option func(*Options)

type Options struct {
	SnapLen     int
	Promiscuous bool
	Filter      string // expression pcap-filter, vide = pas de filtre kernel
}

func DefaultOptions() Options {
	return Options{SnapLen: 65535, Promiscuous: true}
}

func WithSnapLen(n int) Option      { return func(o *Options) { o.SnapLen = n } }
func WithPromiscuous(b bool) Option { return func(o *Options) { o.Promiscuous = b } }
func WithFilter(expr string) Option { return func(o *Options) { o.Filter = expr } }

type Handle struct {
	fd      int
	ifindex int
	opts    Options
	recvBuf []byte
}

func Open(iface string, opts ...Option) (*Handle, error) {
	o := DefaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return open(iface, o)
}

func (h *Handle) Close() error { return closeHandle(h) }
func (h *Handle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return readPacket(h)
}
func (h *Handle) LinkType() gopacket.Decoder { return linkType() }
