//go:build windows

package windivert

import "unsafe"

// Address contient les metadonnees d'un paquet WinDivert (WINDIVERT_ADDRESS).
// Taille totale: 88 bytes (verifiee contre windivert.h v2.x).
//
// Layout memoire:
//   [0x00] Timestamp  int64   (8 bytes)
//   [0x08] Flags      uint32  (4 bytes) - bitfield layer/event/flags
//   [0x0C] Reserved2  uint32  (4 bytes)
//   [0x10] Union      [64]byte (64 bytes) - Network/Flow/Socket/Reflect
//   [0x50] Reserved3  [2]uint32 (8 bytes)
type Address struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Union     [64]byte
	Reserved3 [2]uint32
}

// Verification statique de la taille (88 bytes).
var _ = [1]struct{}{}[unsafe.Sizeof(Address{})-88]

// Layer extrait le layer WinDivert (bits 7:0 de Flags).
func (a *Address) Layer() Layer { return Layer(a.Flags & 0xFF) }

// Event extrait l'event WinDivert (bits 15:8 de Flags).
func (a *Address) Event() uint8 { return uint8((a.Flags >> 8) & 0xFF) }

// IsSniffed retourne true si le paquet est en mode sniff.
func (a *Address) IsSniffed() bool { return a.Flags&(1<<16) != 0 }

// IsOutbound retourne true si le paquet est sortant.
func (a *Address) IsOutbound() bool { return a.Flags&(1<<17) != 0 }

// IsLoopback retourne true si le paquet est loopback.
func (a *Address) IsLoopback() bool { return a.Flags&(1<<18) != 0 }

// IsIPv6 retourne true si le paquet est IPv6.
func (a *Address) IsIPv6() bool { return a.Flags&(1<<20) != 0 }

// NetworkData retourne les donnees reseau (valide si Layer == LayerNetwork/Forward).
func (a *Address) NetworkData() *NetworkData {
	return (*NetworkData)(unsafe.Pointer(&a.Union[0]))
}

// NetworkData contient les metadonnees reseau (WINDIVERT_DATA_NETWORK).
type NetworkData struct {
	IfIdx    uint32 // interface index
	SubIfIdx uint32 // sub-interface index
}
