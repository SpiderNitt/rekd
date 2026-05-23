#!/bin/bash
SERVICE_NAME="rekd"
BINARY_NAME="rekd"
INSTALL_DIR="/usr/local/bin"

if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Please run as root (sudo ./scripts/uninstall.sh)"
  exit 1
fi

echo "[*] Stopping $SERVICE_NAME..."
systemctl stop $SERVICE_NAME || true
systemctl disable $SERVICE_NAME || true

echo "[*] Cleaning up files..."
rm -f /etc/systemd/system/${SERVICE_NAME}.service
rm -f $INSTALL_DIR/$BINARY_NAME
systemctl daemon-reload

echo "✅ Rekd uninstalled."
