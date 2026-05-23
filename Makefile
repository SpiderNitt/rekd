BINARY    := rekd
INSTALL   := /usr/local/bin

.PHONY: all build generate install clean

all: build

# Produces a fully static binary (CGO_ENABLED=0).
# cilium/ebpf is pure Go — no shared libraries needed on the target.
# The BPF .o files must already exist (either from git or `make generate`).
build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) ./cmd/rekd

# Recompile the BPF C program and regenerate Go bindings.
# Requires: clang, llvm, libbpf-dev  (build-time only; not needed to run)
#   Debian/Ubuntu: sudo apt install clang llvm libbpf-dev
#   Fedora/RHEL:   sudo dnf install clang llvm libbpf-devel
# After this, commit the updated .o files:
#   git add internal/bpf/bpf_bpf*.o
generate:
	go generate ./internal/bpf/...

install: build
	@[ "$$(id -u)" = "0" ] || { echo "Error: run as root (sudo make install)"; exit 1; }
	install -m 755 $(BINARY) $(INSTALL)/$(BINARY)

clean:
	rm -f $(BINARY)
