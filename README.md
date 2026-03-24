# Rekd (eBPF Ransomware Scanner)

Rekd (formerly ebpf-ransom-watch) is a high-performance, kernel-level ransomware detection engine. It utilizes eBPF technology to hook the Virtual File System (VFS) layer, calculating the mathematical randomness (Shannon Entropy) of data being written to disk to catch ransomware in real-time.

---

## 🧠 System Design & Methodology

Ransomware possesses one unavoidable property: it must write highly randomized, encrypted ciphertext to the disk. By mathematically evaluating these writes, we can detect cryptographic extortion regardless of the malware's obfuscation, packing, or polymorphism. 

### Minimal Kernel Instrumentation
Scanning every single syscall is impossible without catastrophically degrading storage throughput. To maintain performance, this engine uses minimal, highly targeted kernel scaffolding:

- **fentry Hooks**: We discarded legacy kprobes (which incur massive context-switch latency via software breakpoints) in favor of fast-entry (`fentry`) BPF trampolines. This provides syncronous, near-zero latency access to the `vfs_write` buffers.
- **The 512-Byte Choke Point**: The Linux OS generates thousands of micro-writes per second (e.g., SQLite WALs). The engine strictly drops any write smaller than 512 bytes inside the kernel. Furthermore, it applies a bitwise mask (`0x8000`) to the inode `i_mode` to ensure it only tracks explicit writes to regular files (ignoring sockets and pipes).
- **Scattered Read Extraction**: To bypass strict eBPF verifier memory limits without missing critical data, the engine applies a **Scattered Read** strategy with a 1536-byte max limit. For massive writes, it captures three targeted 512-byte chunks (the header, the midpoint, and the footer) to construct a holistic representation of the payload.

### The Math & Heuristics
100% of the floating-point logarithmic math is performed asynchronously in userspace, ensuring the kernel is never blocked. 

- **Shannon Entropy**: The engine computes the byte distribution entropy, scoring from `0.0` to `8.0`. A strict **Entropy Threshold of 7.5** is established.
- **False Positive Gating**: Benign compression (like gzip or zlib) also writes high-entropy data. To prevent false positives, a state-tracking gate is enforced:
  - **70% Ratio Gate**: A process must demonstrate that at least 70% of its total VFS write volume is strictly high-entropy.
  - **1MB Cumulative Gate**: A process must write a cumulative total of at least 1MB of high-entropy ciphertext before an alert is authorized.

### Architectural Blindspots
- **Vectorized Writes (`vfs_writev`)**: To maximize encryption speed, advanced syndicates like Akira use vectorized I/O (`pwritev`) to pass multiple memory buffers to the kernel in a single syscall. Due to eBPF verifier loop complexities, `vfs_writev` is currently omitted.
- **Entropy Sharing**: Future ransomware variants may use mathematically disjointed ciphertext shares to manually lower their entropy footprint to ~5.0, bypassing standard detection thresholds.

---

## 🚀 Performance
- **Go Implementation**: Designed to decouple buffer extraction from the heavy math calculations. Contributes to less than **1.4% idle CPU overhead**.
- **Python POC**: Over 6% CPU overhead (archived in `poc/`).

---

## 📂 Repository Structure

- `cmd/rekd/`: Primary Go implementation and TUI.
- `internal/bpf/`: eBPF C source code and Go bindings.
- `tests/`: Automated test suite including a dummy AES-CTR encryptor.
- `poc/python/`: Original Python proof-of-concept.
- `scripts/`: Installation and uninstallation scripts.
- `docs/`: Additional documentation.

---

## 📦 Installation & Usage

### 1. Prerequisites
- Linux Kernel with BTF support (standard on modern operating systems).
- BPF Compiler Collection (BCC) and development headers.
- Go compiler.

### 2. Quick Install
Run the provided installation script to compile the eBPF programs, build the Go binary, and register the systemd service:
```bash
sudo ./scripts/install.sh
```

### 3. Usage Modes
- **Daemon Mode**: Built to run entirely in the background. Check logs via:
  ```bash
  sudo systemctl status rekd
  ```
- **Monitor Mode (TUI)**: Stop the daemon and run the binary manually to view a live, dashboard-style UI displaying active PIDs, total writes, and entropy ratios.

---

## 🛡️ Testing
A complete AES-CTR encryption simulator and automated test runner are located in the `tests/` directory. Refer to [tests/README.md](tests/README.md) for execution details.

> [!NOTE]
> Running the test suite will locally generate a `thekey.key` file in your environment. This AES encryption key is used exclusively by the testing simulator and is deliberately preserved. It is ignored by Git and can be safely disregarded.

---

*Proudly Spider R&D Cybersecurity*
