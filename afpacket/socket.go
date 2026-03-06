//go:build linux

package afpacket

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
	pkgbpf "pkt/bpf"
)

func htons(i uint16) uint16 { return (i << 8) | (i >> 8) }

func open(iface string, o Options) (*Handle, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	sll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, &sll); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}

	h := &Handle{fd: fd, opts: o}

	if o.Promiscuous {
		if err := setPromiscuous(fd, ifi.Index, true); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}

	if o.Filter != "" {
		instr, err := pkgbpf.Compile(o.Filter)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("bpf filter: %w", err)
		}
		if err := pkgbpf.Attach(fd, instr); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("attach bpf: %w", err)
		}
	}

	return h, nil
}

func closeHandle(h *Handle) error { return unix.Close(h.fd) }
