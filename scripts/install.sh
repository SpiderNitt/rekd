#!/bin/bash
# rekd installer: deploys a pre-built static binary or builds from source.
# Runtime requirements: Linux >= 5.8 with CONFIG_DEBUG_INFO_BTF=y, root.
set -e

SERVICE_NAME="rekd"
BINARY_NAME="rekd"
INSTALL_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Preflight checks ---

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo ./scripts/install.sh)"
    exit 1
fi

KERNEL_VER="$(uname -r)"
KERNEL_MAJOR="$(echo "$KERNEL_VER" | cut -d. -f1)"
KERNEL_MINOR="$(echo "$KERNEL_VER" | cut -d. -f2 | grep -o '^[0-9]*')"

echo "[*] Kernel: $KERNEL_VER"

if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 8 ]; }; then
    echo "Error: kernel $KERNEL_MAJOR.$KERNEL_MINOR is too old."
    echo "  rekd requires Linux >= 5.8 (BPF ring buffer + fentry trampolines)."
    echo "  Compatible distros: Ubuntu 20.10+, Fedora 31+, Debian 12+, Arch (rolling)."
    exit 1
fi

if [ ! -f "/sys/kernel/btf/vmlinux" ]; then
    echo "Error: kernel BTF not available (/sys/kernel/btf/vmlinux missing)."
    echo "  rekd is a CO-RE binary and requires CONFIG_DEBUG_INFO_BTF=y."
    echo "  This is enabled by default on Ubuntu 20.10+, Fedora 31+, Debian 12+, RHEL 8+."
    echo "  To check: zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF"
    exit 1
fi

# --- Build (if pre-built binary not present) ---

cd "$REPO_ROOT"

if [ -f "$BINARY_NAME" ]; then
    echo "[*] Using pre-built binary: $REPO_ROOT/$BINARY_NAME"
else
    echo "[*] No pre-built binary found. Building from source..."

    if ! command -v go &>/dev/null; then
        echo "Error: 'go' not found. Install Go >= 1.21 to build from source."
        echo "  https://go.dev/dl/"
        exit 1
    fi

    # The BPF .o files are committed to the repo; clang is only needed if they
    # are missing (e.g., after changing main.bpf.c).
    if [ ! -f "internal/bpf/bpf_bpfel.o" ]; then
        echo "[*] BPF objects missing. Installing build dependencies..."
        if command -v apt-get &>/dev/null; then
            apt-get update -y
            apt-get install -y clang llvm libbpf-dev
        elif command -v dnf &>/dev/null; then
            dnf install -y clang llvm libbpf-devel
        else
            echo "Error: cannot auto-install build deps. Install clang, llvm, libbpf-dev manually."
            exit 1
        fi
        echo "[*] Generating BPF objects..."
        go generate ./internal/bpf/...
    fi

    echo "[*] Building rekd (static binary, CGO_ENABLED=0)..."
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BINARY_NAME" ./cmd/rekd
fi

# --- Install binary ---

echo "[*] Installing binary to $INSTALL_DIR/$BINARY_NAME..."
install -m 755 "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"

# --- Create systemd service ---

echo "[*] Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Rekd - eBPF Ransomware Encryption Kernel Detector
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/$BINARY_NAME --daemon
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "✅ Rekd installed and started."
echo "   Status: sudo systemctl status $SERVICE_NAME"
echo "   Logs:   sudo journalctl -u $SERVICE_NAME -f"
