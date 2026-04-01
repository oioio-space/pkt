module github.com/oioio-space/pkt/examples

go 1.25.0

replace (
	github.com/oioio-space/pkt/afpacket => ../afpacket
	github.com/oioio-space/pkt/capture  => ../capture
	github.com/oioio-space/pkt/windivert => ../windivert
)

require (
	github.com/google/gopacket v1.1.19
	github.com/oioio-space/pkt/afpacket v0.0.0-00010101000000-000000000000
	github.com/oioio-space/pkt/capture v0.0.0-00010101000000-000000000000
	github.com/oioio-space/pkt/windivert v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
