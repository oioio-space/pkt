//go:build windows

package filter

import (
	"fmt"
	"strings"
)

// FieldKind décrit le type d'un champ WinDivert.
type FieldKind uint8

const (
	KindBool   FieldKind = iota
	KindUint8
	KindUint16
	KindUint32
	KindUint64
	KindIPv4
	KindIPv6
)

// FieldDef définit un champ WinDivert connu.
type FieldDef struct {
	ID   uint32    // identifiant dans le bytecode
	Kind FieldKind
}

// fieldTable maps field path → FieldDef
var fieldTable = map[string]FieldDef{
	"Zero": {0, KindUint8}, "Event": {1, KindUint8},
	"Random8": {2, KindUint8}, "Random16": {3, KindUint16},
	"Random32": {4, KindUint32}, "Timestamp": {5, KindUint64},
	"Length": {6, KindUint16},
	// IPv4
	"ip":           {10, KindBool},
	"ip.HdrLength": {11, KindUint8}, "ip.TOS": {12, KindUint8},
	"ip.Length": {13, KindUint16}, "ip.Id": {14, KindUint16},
	"ip.MF": {15, KindBool}, "ip.FragOff": {16, KindUint16},
	"ip.TTL": {17, KindUint8}, "ip.Protocol": {18, KindUint8},
	"ip.Checksum": {19, KindUint16},
	"ip.SrcAddr":  {20, KindIPv4}, "ip.DstAddr": {21, KindIPv4},
	// IPv6
	"ipv6":              {30, KindBool},
	"ipv6.TrafficClass": {31, KindUint8}, "ipv6.FlowLabel": {32, KindUint32},
	"ipv6.Length": {33, KindUint16}, "ipv6.NextHdr": {34, KindUint8},
	"ipv6.HopLimit": {35, KindUint8},
	"ipv6.SrcAddr":  {36, KindIPv6}, "ipv6.DstAddr": {37, KindIPv6},
	// TCP
	"tcp":         {40, KindBool},
	"tcp.SrcPort": {41, KindUint16}, "tcp.DstPort": {42, KindUint16},
	"tcp.SeqNum": {43, KindUint32}, "tcp.AckNum": {44, KindUint32},
	"tcp.HdrLength": {45, KindUint8},
	"tcp.Ns":        {46, KindBool}, "tcp.Cwr": {47, KindBool},
	"tcp.Ece": {48, KindBool}, "tcp.Urg": {49, KindBool},
	"tcp.Ack": {50, KindBool}, "tcp.Psh": {51, KindBool},
	"tcp.Rst": {52, KindBool}, "tcp.Syn": {53, KindBool},
	"tcp.Fin": {54, KindBool}, "tcp.Window": {55, KindUint16},
	"tcp.Checksum":      {56, KindUint16}, "tcp.UrgPtr": {57, KindUint16},
	"tcp.PayloadLength": {58, KindUint16},
	// UDP
	"udp":         {60, KindBool},
	"udp.SrcPort": {61, KindUint16}, "udp.DstPort": {62, KindUint16},
	"udp.Length":        {63, KindUint16}, "udp.Checksum": {64, KindUint16},
	"udp.PayloadLength": {65, KindUint16},
	// ICMP / ICMPv6
	"icmp":          {70, KindBool},
	"icmp.Type":     {71, KindUint8}, "icmp.Code": {72, KindUint8},
	"icmp.Checksum": {73, KindUint16}, "icmp.Body": {74, KindUint32},
	"icmpv6":          {80, KindBool},
	"icmpv6.Type":     {81, KindUint8}, "icmpv6.Code": {82, KindUint8},
	"icmpv6.Checksum": {83, KindUint16}, "icmpv6.Body": {84, KindUint32},
}

// LookupField recherche la définition d'un champ par ses parts.
func LookupField(parts []string) (FieldDef, error) {
	key := strings.Join(parts, ".")
	def, ok := fieldTable[key]
	if !ok {
		return FieldDef{}, fmt.Errorf("unknown WinDivert field: %q", key)
	}
	return def, nil
}
