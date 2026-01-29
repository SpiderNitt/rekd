#!/bin/bash

SERVICE_NAME="scanner"

if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Please run as root (sudo ./uninstall.sh)"
  exit 1
fi

echo "[*] Stopping $SERVICE_NAME..."
systemctl stop $SERVICE_NAME
systemctl disable $SERVICE_NAME

if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
    rm "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    echo "✅ Service removed."
else
    echo "⚠️ Service file not found."
fi
