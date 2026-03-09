//go:build windows

package filter

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Sentinel jump-target values used during compilation (replaced by patchJumps).
const (
	acceptSentinel uint16 = 0xFFFF // → len(prog)   = ACCEPT
	rejectSentinel uint16 = 0xFFFE // → len(prog)+1 = REJECT
)

// FilterObject holds one instruction in the WinDivert filter bytecode.
// Wire layout (24 bytes, matches WINDIVERT_FILTER in windivert_device.h):
//
//	word0 [31:16]=success [15:11]=test [10:0]=field
//	word1 [31:17]=reserved [16]=neg [15:0]=failure
//	arg[0..3] = 128-bit comparison value
//
// Use Bytes() to serialize to the wire format.
type FilterObject struct {
	Field   uint32    // 11-bit field ID (WINDIVERT_FILTER_FIELD_*)
	Test    uint8     // 5-bit test code (testEQ..testFalse)
	Neg     uint8     // 1-bit negation flag
	Success uint16    // 16-bit success jump index (or acceptSentinel/rejectSentinel)
	Failure uint16    // 16-bit failure jump index (or acceptSentinel/rejectSentinel)
	Arg     [4]uint32 // 128-bit comparison value
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

// Compile compiles a WinDivert 2.x filter string into bytecode objects.
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
		c.prog = append(c.prog, FilterObject{
			Test: test, Success: acceptSentinel, Failure: rejectSentinel,
		})
	case *FieldNode:
		def, err := LookupField(node.Parts)
		if err != nil {
			return err
		}
		c.prog = append(c.prog, FilterObject{
			Field: def.ID, Test: testTrue, Success: acceptSentinel, Failure: rejectSentinel,
		})
	case *CmpNode:
		return c.emitCmp(node)
	case *UnaryNode:
		start := len(c.prog)
		if err := c.emit(node.Child); err != nil {
			return err
		}
		// NOT: swap accept ↔ reject sentinels; leave resolved indices unchanged.
		for i := start; i < len(c.prog); i++ {
			c.prog[i].Success = swapSentinel(c.prog[i].Success)
			c.prog[i].Failure = swapSentinel(c.prog[i].Failure)
		}
	case *BinaryNode:
		return c.emitBinary(node)
	default:
		return fmt.Errorf("unknown node type %T", n)
	}
	return nil
}

func swapSentinel(v uint16) uint16 {
	switch v {
	case acceptSentinel:
		return rejectSentinel
	case rejectSentinel:
		return acceptSentinel
	}
	return v // resolved index — leave as-is
}

func (c *compiler) emitCmp(n *CmpNode) error {
	def, err := LookupField(n.Field)
	if err != nil {
		return err
	}
	arg, err := parseValue(n.Value, n.VTok, def.Kind)
	if err != nil {
		return err
	}
	c.prog = append(c.prog, FilterObject{
		Field:   def.ID,
		Arg:     arg,
		Test:    opToTest(n.Op),
		Success: acceptSentinel,
		Failure: rejectSentinel,
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

	// Resolve unresolved jumps in the LEFT operand only.
	// Right operand's sentinels are left for patchJumps or outer expressions.
	if n.Op == "and" {
		// AND: left success → check right (leftEnd); left failure → stays rejectSentinel.
		for i := leftStart; i < leftEnd; i++ {
			if c.prog[i].Success == acceptSentinel {
				c.prog[i].Success = uint16(leftEnd)
			}
		}
	} else { // or
		// OR: left failure → check right (leftEnd); left success → stays acceptSentinel.
		for i := leftStart; i < leftEnd; i++ {
			if c.prog[i].Failure == rejectSentinel {
				c.prog[i].Failure = uint16(leftEnd)
			}
		}
	}
	return nil
}

// patchJumps replaces remaining sentinels with final ACCEPT/REJECT indices.
func (c *compiler) patchJumps() {
	accept := uint16(len(c.prog))   // ACCEPT = one past last instruction
	reject := uint16(len(c.prog)) + 1 // REJECT = two past last instruction
	for i := range c.prog {
		if c.prog[i].Success == acceptSentinel {
			c.prog[i].Success = accept
		} else if c.prog[i].Success == rejectSentinel {
			c.prog[i].Success = reject
		}
		if c.prog[i].Failure == acceptSentinel {
			c.prog[i].Failure = accept
		} else if c.prog[i].Failure == rejectSentinel {
			c.prog[i].Failure = reject
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
	var arg [4]uint32
	switch tok {
	case "number":
		// raw may be "80" (decimal) or "0x06" (hex with 0x prefix).
		s := strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
		n, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			// Not hex: try decimal
			n, err = strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return arg, fmt.Errorf("invalid number %q", raw)
			}
		}
		arg[0] = uint32(n)
		arg[1] = uint32(n >> 32)
	case "ipaddr":
		ip := net.ParseIP(raw).To4()
		if ip == nil {
			return arg, fmt.Errorf("invalid IPv4 %q", raw)
		}
		arg[0] = binary.BigEndian.Uint32(ip)
	case "ip6addr":
		ip := net.ParseIP(raw).To16()
		if ip == nil {
			return arg, fmt.Errorf("invalid IPv6 %q", raw)
		}
		arg[0] = binary.BigEndian.Uint32(ip[0:4])
		arg[1] = binary.BigEndian.Uint32(ip[4:8])
		arg[2] = binary.BigEndian.Uint32(ip[8:12])
		arg[3] = binary.BigEndian.Uint32(ip[12:16])
	}
	return arg, nil
}

// Bytes serializes a filter program to the 24-byte-per-instruction wire format
// expected by DeviceIoControl(IOCTL_WINDIVERT_STARTUP).
//
// Wire format (little-endian):
//
//	word0: field[10:0] | test[15:11] | success[31:16]
//	word1: failure[15:0] | neg[16] | reserved[31:17]
//	word2..5: arg[0..3]
func Bytes(prog []FilterObject) []byte {
	buf := make([]byte, len(prog)*24)
	for i, obj := range prog {
		off := i * 24
		word0 := (obj.Field & 0x7FF) | (uint32(obj.Test)&0x1F)<<11 | uint32(obj.Success)<<16
		word1 := uint32(obj.Failure) | uint32(obj.Neg&1)<<16
		binary.LittleEndian.PutUint32(buf[off:], word0)
		binary.LittleEndian.PutUint32(buf[off+4:], word1)
		binary.LittleEndian.PutUint32(buf[off+8:], obj.Arg[0])
		binary.LittleEndian.PutUint32(buf[off+12:], obj.Arg[1])
		binary.LittleEndian.PutUint32(buf[off+16:], obj.Arg[2])
		binary.LittleEndian.PutUint32(buf[off+20:], obj.Arg[3])
	}
	return buf
}
