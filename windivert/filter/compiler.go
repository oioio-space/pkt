//go:build windows

package filter

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unsafe"
)

// FilterObject is a WinDivert bytecode object passed to the driver via DeviceIoControl.
type FilterObject struct {
	Val     [4]uint32
	Field   uint32
	Test    uint8
	Neg     uint8
	Success uint16
	Failure uint16
}

const (
	testEQ    uint8 = 0
	testNEQ   uint8 = 1
	testLT    uint8 = 2
	testLE    uint8 = 3
	testGT    uint8 = 4
	testGE    uint8 = 5
	testTrue  uint8 = 6
	testFalse uint8 = 7
)

// Compile compiles a WinDivert 2.x filter string into bytecode.
func Compile(filterStr string) ([]FilterObject, error) {
	ast, err := Parse("filter", []byte(filterStr))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	c := &compiler{}
	if err := c.emit(ast.(Node)); err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	c.patchJumps()
	return c.prog, nil
}

type compiler struct {
	prog []FilterObject
}

func (c *compiler) emit(n Node) error {
	switch node := n.(type) {
	case *BoolNode:
		test := testTrue
		if !node.Value {
			test = testFalse
		}
		c.prog = append(c.prog, FilterObject{Test: test})
	case *FieldNode:
		def, err := LookupField(node.Parts)
		if err != nil {
			return err
		}
		c.prog = append(c.prog, FilterObject{Field: def.ID, Test: testTrue})
	case *CmpNode:
		return c.emitCmp(node)
	case *UnaryNode:
		start := len(c.prog)
		if err := c.emit(node.Child); err != nil {
			return err
		}
		for i := start; i < len(c.prog); i++ {
			c.prog[i].Success, c.prog[i].Failure = c.prog[i].Failure, c.prog[i].Success
			c.prog[i].Neg ^= 1
		}
	case *BinaryNode:
		return c.emitBinary(node)
	default:
		return fmt.Errorf("unknown node type %T", n)
	}
	return nil
}

func (c *compiler) emitCmp(n *CmpNode) error {
	def, err := LookupField(n.Field)
	if err != nil {
		return err
	}
	val, err := parseValue(n.Value, n.VTok, def.Kind)
	if err != nil {
		return err
	}
	c.prog = append(c.prog, FilterObject{
		Field: def.ID,
		Val:   val,
		Test:  opToTest(n.Op),
	})
	return nil
}

func (c *compiler) emitBinary(n *BinaryNode) error {
	leftStart := len(c.prog)
	if err := c.emit(n.Left); err != nil {
		return err
	}
	leftEnd := len(c.prog)
	if err := c.emit(n.Right); err != nil {
		return err
	}
	rightEnd := len(c.prog)

	// AND: left failure → skip right (REJECT); left success → fall through to right
	// OR:  left success → skip right (ACCEPT); left failure → fall through to right
	if n.Op == "and" {
		for i := leftStart; i < leftEnd; i++ {
			c.prog[i].Failure = uint16(rightEnd)
		}
	} else { // or
		for i := leftStart; i < leftEnd; i++ {
			c.prog[i].Success = uint16(rightEnd)
		}
	}
	return nil
}

// patchJumps fills in zero (unset) jump targets with final accept/reject indices.
func (c *compiler) patchJumps() {
	last := uint16(len(c.prog))
	for i := range c.prog {
		if c.prog[i].Success == 0 {
			c.prog[i].Success = last // ACCEPT
		}
		if c.prog[i].Failure == 0 {
			c.prog[i].Failure = last + 1 // REJECT
		}
	}
}

func opToTest(op string) uint8 {
	switch op {
	case "==":
		return testEQ
	case "!=":
		return testNEQ
	case "<":
		return testLT
	case "<=":
		return testLE
	case ">":
		return testGT
	case ">=":
		return testGE
	}
	return testTrue
}

func parseValue(raw, tok string, kind FieldKind) ([4]uint32, error) {
	var val [4]uint32
	switch tok {
	case "number":
		// raw may be "80" (decimal) or "0x06" (hex with prefix)
		s := strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
		n, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			// Not hex — try decimal
			n, err = strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return val, fmt.Errorf("invalid number %q", raw)
			}
		}
		val[0] = uint32(n)
		val[1] = uint32(n >> 32)
	case "ipaddr":
		ip := net.ParseIP(raw).To4()
		if ip == nil {
			return val, fmt.Errorf("invalid IPv4 %q", raw)
		}
		val[0] = binary.BigEndian.Uint32(ip)
	case "ip6addr":
		ip := net.ParseIP(raw).To16()
		if ip == nil {
			return val, fmt.Errorf("invalid IPv6 %q", raw)
		}
		val[0] = binary.BigEndian.Uint32(ip[0:4])
		val[1] = binary.BigEndian.Uint32(ip[4:8])
		val[2] = binary.BigEndian.Uint32(ip[8:12])
		val[3] = binary.BigEndian.Uint32(ip[12:16])
	}
	return val, nil
}

// Bytes serializes a filter program to bytes for DeviceIoControl.
func Bytes(prog []FilterObject) []byte {
	size := len(prog) * int(unsafe.Sizeof(FilterObject{}))
	buf := make([]byte, size)
	for i, obj := range prog {
		off := i * int(unsafe.Sizeof(obj))
		copy(buf[off:], (*[unsafe.Sizeof(FilterObject{})]byte)(unsafe.Pointer(&obj))[:])
	}
	return buf
}
