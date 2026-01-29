#!/bin/bash

SERVICE_NAME="scanner"
SCRIPT_NAME="scanner.py"
LOG_FILE="activity.log"
CONFIG_FILE="exclusions.yaml"

# 1. Check for Root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Please run as root (sudo ./install.sh)"
  exit 1
fi

# 2. Get Absolute Path
WORK_DIR=$(pwd)
echo "[*] Installing from directory: $WORK_DIR"

# 3. Install Dependencies
echo "[*] Installing Python requirements..."
pip3 install rich pyyaml

# 4. Generate Default Config
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[*] Creating default $CONFIG_FILE..."
    python3 "$WORK_DIR/$SCRIPT_NAME" --init-config
fi

# 5. Create Systemd Service
echo "[*] Creating systemd service..."

cat <<EOF > /etc/systemd/system/${SERVICE_NAME}.service
[Unit]
Description=Encrypted IO BPF Scanner
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${WORK_DIR}
# Run python unbuffered (-u) with daemon mode
ExecStart=/usr/bin/python3 -u ${WORK_DIR}/${SCRIPT_NAME} --daemon --log ${WORK_DIR}/${LOG_FILE} --config ${WORK_DIR}/${CONFIG_FILE}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 6. Enable and Start
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

echo "✅ Service Installed & Started!"
echo "   - Logs: $WORK_DIR/$LOG_FILE"
echo "   - Status: sudo systemctl status $SERVICE_NAME"