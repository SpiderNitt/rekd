package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang Bpf main.bpf.c -- -I/usr/include/bpf
