// Package bpf compiles pcap-filter expressions into BPF bytecode
// and attaches the resulting filters to AF_PACKET sockets via SO_ATTACH_FILTER.
//
// # Usage
//
//	instrs, err := bpf.Compile("tcp port 80")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if err := bpf.Attach(fd, instrs); err != nil {
//	    log.Fatal(err)
//	}
//
// # Requirements
//
// Linux only.
package bpf
