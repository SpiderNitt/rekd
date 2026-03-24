# Rekd Detection Testing Suite

This directory contains standalone tools and scripts designed to test the detection capabilities of the `rekd` eBPF ransomware scanner. The tests simulate rapid encryption and measure the scanner's response time and damage mitigation.

## Components

### 1. `dummy_ransomware/`
A Go program that simulates ransomware behavior by rapidly encrypting files in a specified directory using AES-CTR. It does *not* delete originals until the encrypted copy is safely written, mimicking real-world malicious actors.
- **Source**: `main.go`
- **Usage**: `./dummy_ransomware <E/D> <Target_Directory>` 
- **Note**: Executing this simulation will locally generate a `thekey.key` file in your environment. This is the AES encryption key used strictly by the testing suite. It is deliberately preserved and safely ignored by Git.

### 2. `run_tests.sh`
An automated bash script that orchestrates the detection test.
- Generates a mixed dataset of dummy files (100KB and 2MB) in `test_data/`.
- Starts the `rekd` scanner in background daemon mode.
- Executes the `dummy_ransomware` against the `test_data/` directory.
- Parses the scanner's output logs to identify "High Entropy Write Detected" events.
- Calculates total attack duration and evaluates how many files were successfully encrypted before detection.

## How to Run the Tests

To execute the automated test mesh:

1. Ensure the main `rekd` scanner is built (the script will attempt to build it if missing).
2. Execute the test runner **as root** (eBPF requires root privileges):

```bash
sudo ./run_tests.sh
```

### Expected Output
The script will output `[+] SUCCESS: Rekd successfully detected high entropy writes.` along with the first detection timestamp and the number of detection events flagged. It will also output the number of files the dummy ransomware managed to encrypt.
