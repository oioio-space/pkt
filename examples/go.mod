module pkt/examples

go 1.25.0

replace (
	pkt/afpacket => ../afpacket
	pkt/windivert => ../windivert
)

require (
	github.com/google/gopacket v1.1.19
	pkt/afpacket v0.0.0-00010101000000-000000000000
	pkt/windivert v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
