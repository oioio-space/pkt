//go:build windows

// Package filter compile des filtres WinDivert 2.x en bytecode driver.
// La grammaire est definie dans grammar.peg -- grammar.go est genere (ne pas editer).
//
//go:generate pigeon -o grammar.go grammar.peg
package filter
