package bpf

// CO-RE build: clang + libbpf-dev required at build time only.
// The compiled .o is embedded in the final binary; the target machine
// needs no build tools — just Linux >= 5.8 with CONFIG_DEBUG_INFO_BTF=y.
//
// After changing main.bpf.c, regenerate with:
//   apt install clang llvm libbpf-dev   # or dnf equivalent
//   go generate ./internal/bpf/...
//   git add internal/bpf/bpf_bpf*.o
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Bpf main.bpf.c -- -O2 -g -Wall -I/usr/include/bpf
