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
	ID   uint32    // identifiant dans le bytecode (WINDIVERT_FILTER_FIELD_*)
	Kind FieldKind
}

// fieldTable maps filter-language field path → FieldDef.
// IDs are taken verbatim from windivert_device.h (WINDIVERT_FILTER_FIELD_*).
var fieldTable = map[string]FieldDef{
	// Meta / always-constant
	"Zero": {0, KindUint8},
	// Direction (network / network-forward layers)
	"inbound":  {1, KindBool},
	"outbound": {2, KindBool},
	// Interface
	"ifIdx":    {3, KindUint32},
	"subIfIdx": {4, KindUint32},
	// Protocol presence (boolean)
	"ip":     {5, KindBool},
	"ipv6":   {6, KindBool},
	"icmp":   {7, KindBool},
	"tcp":    {8, KindBool},
	"udp":    {9, KindBool},
	"icmpv6": {10, KindBool},
	// IPv4 header fields
	"ip.HdrLength": {11, KindUint8},
	"ip.TOS":       {12, KindUint8},
	"ip.Length":    {13, KindUint16},
	"ip.Id":        {14, KindUint16},
	"ip.DF":        {15, KindBool},
	"ip.MF":        {16, KindBool},
	"ip.FragOff":   {17, KindUint16},
	"ip.TTL":       {18, KindUint8},
	"ip.Protocol":  {19, KindUint8},
	"ip.Checksum":  {20, KindUint16},
	"ip.SrcAddr":   {21, KindIPv4},
	"ip.DstAddr":   {22, KindIPv4},
	// IPv6 header fields
	"ipv6.TrafficClass": {23, KindUint8},
	"ipv6.FlowLabel":    {24, KindUint32},
	"ipv6.Length":       {25, KindUint16},
	"ipv6.NextHdr":      {26, KindUint8},
	"ipv6.HopLimit":     {27, KindUint8},
	"ipv6.SrcAddr":      {28, KindIPv6},
	"ipv6.DstAddr":      {29, KindIPv6},
	// ICMP header fields
	"icmp.Type":     {30, KindUint8},
	"icmp.Code":     {31, KindUint8},
	"icmp.Checksum": {32, KindUint16},
	"icmp.Body":     {33, KindUint32},
	// ICMPv6 header fields
	"icmpv6.Type":     {34, KindUint8},
	"icmpv6.Code":     {35, KindUint8},
	"icmpv6.Checksum": {36, KindUint16},
	"icmpv6.Body":     {37, KindUint32},
	// TCP header fields
	"tcp.SrcPort":       {38, KindUint16},
	"tcp.DstPort":       {39, KindUint16},
	"tcp.SeqNum":        {40, KindUint32},
	"tcp.AckNum":        {41, KindUint32},
	"tcp.HdrLength":     {42, KindUint8},
	"tcp.Urg":           {43, KindBool},
	"tcp.Ack":           {44, KindBool},
	"tcp.Psh":           {45, KindBool},
	"tcp.Rst":           {46, KindBool},
	"tcp.Syn":           {47, KindBool},
	"tcp.Fin":           {48, KindBool},
	"tcp.Window":        {49, KindUint16},
	"tcp.Checksum":      {50, KindUint16},
	"tcp.UrgPtr":        {51, KindUint16},
	"tcp.PayloadLength": {52, KindUint16},
	// UDP header fields
	"udp.SrcPort":       {53, KindUint16},
	"udp.DstPort":       {54, KindUint16},
	"udp.Length":        {55, KindUint16},
	"udp.Checksum":      {56, KindUint16},
	"udp.PayloadLength": {57, KindUint16},
	// Loopback / impostor flags
	"loopback": {58, KindBool},
	"impostor": {59, KindBool},
	// Packet-level meta (all layers)
	"Length":    {80, KindUint16},
	"Timestamp": {81, KindUint64},
	"Random8":   {82, KindUint8},
	"Random16":  {83, KindUint16},
	"Random32":  {84, KindUint32},
	"Fragment":  {85, KindBool},
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
