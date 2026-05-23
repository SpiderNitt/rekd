# Rekd (Ransomware Encryption Kernel Detector)

Rekd is a high-performance, kernel-level ransomware detection engine. It hooks the Linux VFS write path with eBPF, computing Shannon entropy on write payloads to catch ransomware in real time — regardless of obfuscation, packing, or polymorphism.

Distributed as a **CO-RE + static binary**: one self-contained executable with zero runtime dependencies beyond a modern Linux kernel.

---

## Distribution Model

| Property | Detail |
|----------|--------|
| **CO-RE** | BPF bytecode carries BTF relocations. The kernel resolves types against its own BTF at load time — no kernel headers or libbpf on the target. |
| **Static binary** | Built with `CGO_ENABLED=0`. No shared libraries, no Go installation required on the target. |
| **Runtime requirements** | Linux >= 5.8, `CONFIG_DEBUG_INFO_BTF=y`, root (`sudo`). |
| **Build requirements** | Only needed to modify the BPF C source: `clang`, `llvm`, `libbpf-dev`. |

Rekd checks all prerequisites at startup and prints actionable errors if they are not met.

### Kernel Compatibility

| Distro | Minimum Version | Notes |
|--------|-----------------|-------|
| Ubuntu | 20.10+ | Default kernel >= 5.8, BTF enabled |
| Ubuntu | 20.04 LTS | Needs HWE kernel (5.15+); base 5.4 is too old |
| Fedora | 31+ | BTF enabled by default |
| Debian | 12 (Bookworm)+ | BTF enabled |
| RHEL / CentOS Stream | 9+ | Kernel 5.14+, BTF enabled. RHEL 8 kernel is 4.18 (too old). |
| Arch Linux | Rolling | Always current |

---

## Quick Start

### Run a pre-built binary

```bash
# Verify prerequisites (kernel >= 5.8, BTF, root) — rekd checks these itself.
sudo ./rekd             # interactive TUI
sudo ./rekd --daemon    # background, logs via journald
```

### Install as a systemd service

```bash
sudo ./scripts/install.sh
sudo systemctl status rekd
sudo journalctl -u rekd -f
```

The installer checks kernel compatibility before proceeding and prints clear errors if requirements are not met.

---

## Build from Source

No special tooling is needed to compile the Go binary — the BPF `.o` objects are committed to the repository and embedded at link time.

```bash
make build          # CGO_ENABLED=0, produces ./rekd (static)
sudo make install   # copies to /usr/local/bin
```

### Regenerating BPF objects

Only needed if you modify `internal/bpf/main.bpf.c`:

```bash
# Debian/Ubuntu
sudo apt install clang llvm libbpf-dev

# Fedora/RHEL
sudo dnf install clang llvm libbpf-devel

make generate
git add internal/bpf/bpf_bpf*.o   # commit the updated objects
```

---

## System Design & Methodology

Ransomware possesses one unavoidable property: it must write highly randomized, encrypted ciphertext to disk. By mathematically evaluating these writes, we can detect cryptographic extortion regardless of the malware's obfuscation, packing, or polymorphism.

### Minimal Kernel Instrumentation

Scanning every syscall is impossible without catastrophically degrading storage throughput. Rekd uses minimal, highly targeted kernel scaffolding:

- **fentry Hooks**: Fast-entry (`fentry`) BPF trampolines patch a direct call to `vfs_write`, avoiding costly context switches and software breakpoints used by legacy kprobes.
- **512-Byte Threshold**: Writes smaller than 512 bytes (e.g., SQLite WALs) are dropped in the kernel before data leaves kernel space.
- **Regular File Filter**: A bitwise mask (`inode.i_mode & 0xF000 == 0x8000`) restricts monitoring to regular files, ignoring sockets and pipes.
- **Scattered Read Extraction**: For writes >= 1536 bytes, three targeted 512-byte chunks (header, midpoint, footer) are captured. This bypasses eBPF verifier memory limits while preserving statistical coverage.

### Detection Heuristics

All entropy math is performed asynchronously in userspace — the kernel is never blocked.

- **Shannon Entropy**: Byte distribution scored 0.0–8.0. Threshold: **7.5**. AES ciphertext reliably scores ≥ 7.9.
- **70% Ratio Gate**: At least 70% of a process's total VFS write volume must be high-entropy. Eliminates false positives from tools like gzip.
- **1MB Cumulative Gate**: A process must write at least 1MB of high-entropy data before an alert fires. Eliminates transient false positives.

### Known Architectural Limitations

| Gap | Impact |
|-----|--------|
| `vfs_writev` not hooked | Advanced ransomware (e.g., Akira) uses vectorized I/O (`pwritev`), bypassing rekd entirely |
| One alert per PID | `s.Alerted` is never reset; a pause-resume pattern fires no second alert |
| Scattered sampling | Front-loaded plaintext headers in a write could score below threshold |
| No persistent state | A rekd restart resets all per-PID accumulators |
| `fname` is not a full path | Only the dentry name component is captured, not the full path |
| Silent ring buffer drops | If the 16MB ring buffer fills, events are discarded with no back-pressure |

---

## Performance

- **Go implementation**: < 1.4% idle CPU overhead (entropy math decoupled from kernel path).
- **Python POC** (archived in `poc/`): > 6% CPU overhead.

---

## Usage Modes

**Interactive TUI** (default):
```bash
sudo rekd
```
Live table of active PIDs sorted by encrypted MB. Refresh every 2 seconds. Press `q` to quit.

**Daemon mode**:
```bash
sudo rekd --daemon
# or via systemd:
sudo systemctl start rekd
sudo journalctl -u rekd -f
```
No TUI. Alerts logged via `log.Printf` / systemd journal when a process crosses both detection gates.

---

## Repository Structure

```
rekd/
├── cmd/rekd/
│   └── main.go              — userspace: workers, aggregator, TUI, startup checks
├── internal/bpf/
│   ├── main.bpf.c           — eBPF C program (kernel hook)
│   ├── generate.go          — //go:generate for bpf2go
│   ├── bpf_bpfel.o          — compiled BPF object (little-endian, committed)
│   ├── bpf_bpfeb.o          — compiled BPF object (big-endian, committed)
│   ├── bpf_bpfel.go         — generated Go bindings
│   ├── bpf_bpfeb.go         — generated Go bindings
│   └── vmlinux.h            — kernel BTF header (CO-RE, no kernel headers at runtime)
├── tests/
│   ├── dummy_ransomware/    — AES-CTR file encryptor for testing
│   └── run_tests/           — automated integration test script
├── poc/python/              — original Python POC (archived)
├── scripts/
│   ├── install.sh           — builds (if needed) and installs systemd service
│   └── uninstall.sh         — removes service and binary
├── Makefile                 — build targets (build, generate, install, clean)
└── docs/
    └── ARCHITECTURE.md      — detailed component breakdown
```

---

## Testing

An AES-CTR encryption simulator and automated test runner are in `tests/`. See [tests/README.md](tests/README.md).

> [!NOTE]
> The test suite generates `thekey.key` (AES key for the simulator). It is gitignored and can be safely disregarded.

---

*Proudly Spider R&D Cybersecurity*
