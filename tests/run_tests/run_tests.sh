#!/bin/bash
set -e

echo "=== Rekd Ransomware Detection Test Suite ==="

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test_data"
DUMMY_BIN="$SCRIPT_DIR/../dummy_ransomware/dummy_ransomware"
REKD_BIN="$SCRIPT_DIR/../../cmd/rekd/rekd"

echo "[*] Ensuring root privileges for scanner testing..."
if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Please run tests as root (sudo ./run_tests.sh)"
  exit 1
fi

# Setup Environment
echo "[*] Setting up fresh environment..."
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Generate Dummy Data
echo "[*] Generating dummy files in background..."
# 1000 small files (100KB)
for i in {1..100}; do
    dd if=/dev/urandom of="$TEST_DIR/small_$i.dat" bs=100K count=1 status=none &
done
# 50 large files (2MB)
for i in {1..50}; do
    dd if=/dev/urandom of="$TEST_DIR/large_$i.dat" bs=2M count=1 status=none &
done
wait
echo "[+] Dummy data generated."

# Start Scanner in Background
echo "[*] Starting rekd scanner in daemon mode..."
# Build if necessary
if [ ! -f "$REKD_BIN" ]; then
    echo "    Building rekd..."
    cd "$SCRIPT_DIR/../../cmd/rekd"
    go build -o rekd main.go
    cd "$SCRIPT_DIR"
fi

# Start the scanner, redirecting output to a temporary log
SCANNER_LOG=$(mktemp)
$REKD_BIN --daemon > "$SCANNER_LOG" 2>&1 &
SCANNER_PID=$!
sleep 2 # Give it time to initialize

# Verify it started
if ! ps -p $SCANNER_PID > /dev/null; then
    echo "[-] FAILED: Rekd scanner did not start correctly."
    cat "$SCANNER_LOG"
    exit 1
fi

echo "[!] Executing Dummy Ransomware Attack..."
START_TIME=$(date +%s.%N)

# Run the attack
$DUMMY_BIN E "$TEST_DIR" > /dev/null || true

END_TIME=$(date +%s.%N)
echo "[+] Attack completed."

# Sleep briefly to ensure logs flush
sleep 2

# Stop Scanner
echo "[*] Stopping scanner..."
kill $SCANNER_PID || true
wait $SCANNER_PID 2>/dev/null || true

# --- Analyze Results ---
echo ""
echo "====================================="
echo "          RESULTS ANALYSIS           "
echo "====================================="

# 1. Total Attack Time
ATTACK_DURATION=$(echo "$END_TIME - $START_TIME" | bc)
echo "- Total Attack Execution Time: $(printf "%.2f" $ATTACK_DURATION) seconds"

# 2. Check if detected
echo "[*] Checking scanner logs for detection events..."
DETECTION_COUNT=$(grep -c "High Entropy Write Detected" "$SCANNER_LOG" || true)

if [ "$DETECTION_COUNT" -eq 0 ]; then
   echo "[-] FAILED: Rekd did NOT detect the ransomware activity."
   echo "    Scanner Log Output:"
   cat "$SCANNER_LOG"
else
   echo "[+] SUCCESS: Rekd successfully detected high entropy writes."
   
   # Note: For strict metrics (time to detect), we would need timestamps in the rekd daemon output.
   # Currently, rekd `log.Printf` provides standard Go timestamps (e.g. 2026/03/24 22:04:00).
   
   FIRST_DETECT_LINE=$(grep "High Entropy Write Detected" "$SCANNER_LOG" | head -n 1)
   echo "    First Flag: $FIRST_DETECT_LINE"
   echo "    Total Detection Events Flags: $DETECTION_COUNT"
fi

# 3. Calculate Damage
# Count how many files got .tmp appended (indicating successful encryption by our dummy)
ENCRYPTED_FILES=$(find "$TEST_DIR" -type f -not -name "*.tmp" | wc -l)
echo "- Files Encrypted Before Detection (or Total if undetected): $ENCRYPTED_FILES"

# Cleanup
echo "[*] Cleaning up test data..."
rm -rf "$TEST_DIR"
rm -f "$SCANNER_LOG"
echo "[+] Cleanup complete."
