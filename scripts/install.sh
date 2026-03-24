#!/bin/bash
set -e

SERVICE_NAME="rekd"
BINARY_NAME="rekd"
INSTALL_DIR="/usr/local/bin"

if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Please run as root (sudo ./scripts/install.sh)"
  exit 1
fi

# 1. Install Dependencies
echo "[*] Installing dependencies..."
apt-get update -y || true
apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool golang || echo "⚠️ Some dependencies may already be installed or failed to install. Continuing..."

# 2. Build Go Implementation
echo "[*] Building rekd..."
# Ensure we are in the repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

go generate ./internal/bpf/...
go build -o $BINARY_NAME ./cmd/rekd

# 3. Install Binary
echo "[*] Installing binary to $INSTALL_DIR..."
mv $BINARY_NAME $INSTALL_DIR/

# 4. Create Systemd Service
echo "[*] Creating systemd service..."
cat <<EOF > /etc/systemd/system/${SERVICE_NAME}.service
[Unit]
Description=Rekd eBPF Ransomware Scanner
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/$BINARY_NAME --daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 5. Start Service
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

echo "✅ Rekd Installed & Started!"
echo "   - Status: sudo systemctl status $SERVICE_NAME"