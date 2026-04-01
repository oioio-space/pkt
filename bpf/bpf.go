//go:build linux

package bpf

import (
	"fmt"
	"unsafe"

	goBPF "golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/packetcap/go-pcap/filter"
)

// Compile parse une expression pcap-filter style et retourne les instructions BPF.
// Exemples : "tcp port 80", "ip and tcp", "host 192.168.1.1"
func Compile(expr string) ([]goBPF.Instruction, error) {
	if expr == "" {
		return nil, fmt.Errorf("empty filter expression")
	}
	e := filter.NewExpression(expr)
	f := e.Compile()
	instr, err := f.Compile()
	if err != nil {
		return nil, fmt.Errorf("compile BPF %q: %w", expr, err)
	}
	return instr, nil
}

// Attach attache un filtre BPF à un socket (SO_ATTACH_FILTER).
func Attach(fd int, instructions []goBPF.Instruction) error {
	raw, err := goBPF.Assemble(instructions)
	if err != nil {
		return fmt.Errorf("assemble BPF: %w", err)
	}
	prog := unix.SockFprog{
		Len:    uint16(len(raw)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&raw[0])),
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
}

// Detach retire le filtre BPF d'un socket (SO_DETACH_FILTER).
func Detach(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0)
}
