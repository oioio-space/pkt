package capture

import "github.com/google/gopacket"

// Source is a cross-platform passive packet capture source.
// It implements gopacket.PacketDataSource.
type Source struct {
	inner   gopacket.PacketDataSource
	decoder gopacket.Decoder
	closer  func() error
}

// ReadPacketData implements gopacket.PacketDataSource.
func (s *Source) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return s.inner.ReadPacketData()
}

// LinkType returns the gopacket layer decoder for this source.
func (s *Source) LinkType() gopacket.Decoder { return s.decoder }

// Close closes the underlying capture handle.
func (s *Source) Close() error { return s.closer() }
