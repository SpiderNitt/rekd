#!/bin/bash

set -euo pipefail

echo "[*] Setting up eBPF Development Environment..."

KERNEL_VERSION="$(uname -r)"

# 1. Update package list (ignore unrelated repo signature failures)
# We use sudo here so we don't have to run the whole script as root
sudo apt-get update -y || true

# 2. Install required packages
echo "[*] Installing dependencies..."
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-"${KERNEL_VERSION}" \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-"${KERNEL_VERSION}" \
    bpftool || echo "[-] Some packages failed, but trying to proceed..."

# 3. Ensure kernel headers exist
if [ ! -d "/lib/modules/${KERNEL_VERSION}" ]; then
    echo "[-] Kernel headers missing for ${KERNEL_VERSION}"
    exit 1
fi

# 4. Dependency Management (THE FIX)
echo "[*] Checking Go dependencies..."
if [ ! -f "go.mod" ]; then
    go mod init rekd_agent
fi

# Always ensure these are present. It's fast and prevents the "missing package" error.
go get github.com/charmbracelet/bubbles/table
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss
go get github.com/cilium/ebpf
go mod tidy

# 5. Generate vmlinux.h from BTF
echo "[*] Generating vmlinux.h from kernel BTF..."
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "[-] Kernel BTF not found. Ensure CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi
# Using sudo only for the dump command
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 6. Clean and Generate
echo "[*] Cleaning old BPF generated files..."
rm -f bpf_*.go bpf_*.o

echo "[*] Running bpf2go code generation..."
go generate

# 7. Build binary
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BIN_NAME="rekd_${TIMESTAMP}"

echo "[*] Building optimized binary: ${BIN_NAME}"
go build -ldflags "-s -w" -o "${BIN_NAME}"

echo "[*] Build complete. Launching..."
echo "--------------------------------------------------------"

# 8. Run with root privileges
# This works because the script is running as USER, but this specific command requests sudo
sudo "./${BIN_NAME}"