# rekd Architecture

**Ransomware Encryption Kernel Detector** — a Linux kernel-level ransomware detection engine using eBPF and Shannon entropy analysis.

---

## Distribution Model: CO-RE + Static Binary

rekd ships as a single self-contained executable:

- **CO-RE (Compile Once — Run Everywhere)**: The BPF object is compiled with `-g` (BTF debug info) and uses `BPF_CORE_READ` for all kernel struct accesses. At load time, the kernel applies BTF relocations against its own type information. The same binary runs on any compatible kernel without kernel headers or libbpf installed on the target.
- **Static Go binary**: Built with `CGO_ENABLED=0`. cilium/ebpf is pure Go; the compiled BPF bytecode is embedded via `//go:embed`. The resulting binary has zero shared library dependencies.

**Runtime requirements**: Linux >= 5.8 with BTF (`/sys/kernel/btf/vmlinux` present), root.  
**Build requirements** (only if modifying BPF C source): `clang`, `llvm`, `libbpf-dev`.

`CONFIG_DEBUG_INFO_BTF=y` is enabled by default on every mainstream distribution that ships kernel >= 5.8 (Ubuntu 20.10+, Fedora 31+, Debian 11+, RHEL 9+, Arch). If rekd is running on a stock distro kernel, BTF will be present. Custom or minimal kernels are the only realistic exception; rekd checks at startup and prints an actionable error if BTF is missing.

The BPF `.o` objects (`internal/bpf/bpf_bpf*.o`) are committed to the repository so that `go build` / `make build` works without a clang installation.

---

## What it does in one paragraph

rekd hooks the `vfs_write` kernel function using an eBPF fentry trampoline. Every file write larger than 512 bytes hits this hook, which samples up to 1536 bytes of the payload and ships it to userspace via a ring buffer. Four worker goroutines compute Shannon entropy on each sample. A stats aggregator tracks cumulative write volumes per PID and fires an alert when a process has written more than 1MB of high-entropy data and more than 70% of its total write volume is high-entropy. This two-gate system is what separates ransomware from benign tools like gzip.

---

## System Layers

```
┌─────────────────────────────────────────────────────────┐
│  KERNEL SPACE                                           │
│                                                         │
│   vfs_write() ──► fentry hook (main.bpf.c)             │
│                       │                                 │
│                   [filter: size >= 512, regular file]   │
│                       │                                 │
│                   [scattered read: 3×512B chunks]       │
│                       │                                 │
│                   ring buffer (16MB)                    │
└───────────────────────┼─────────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────────┐
│  USERSPACE (Go)       │                                 │
│                       ▼                                 │
│           reader goroutine                              │
│                       │                                 │
│                   eventsChan (chan []byte, cap 10k)      │
│                       │                                 │
│           ┌──┬──┬──┬──┘                                 │
│           ▼  ▼  ▼  ▼                                    │
│       4 worker goroutines                               │
│       (Shannon entropy calc via LUT)                    │
│           │                                             │
│       updatesChan (chan UpdatePayload, cap 10k)          │
│           │                                             │
│           ▼                                             │
│       stats aggregator goroutine                        │
│       (per-PID accounting + alerting gate)              │
│           │                                             │
│     ┌─────┴────────┐                                    │
│     ▼              ▼                                    │
│  TUI mode      Daemon mode                              │
│  (2s refresh)  (log.Printf alerts)                      │
└─────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. eBPF Hook (`internal/bpf/main.bpf.c`)

Attached via **fentry trampoline** — not a kprobe. fentry patches a direct call using BPF trampolines instead of a software breakpoint, meaning there's no context-switch overhead. This is the key performance win over legacy implementations.

**Filters applied inside the kernel (before any data leaves):**

| Filter | Reason |
|--------|--------|
| `size < 512` → drop | Eliminates thousands of micro-writes per second (SQLite WALs, etc.) |
| `inode mode & 0xF000 != 0x8000` → drop | Only regular files; ignores sockets, pipes, device files |

**Scattered read strategy** (why this matters):

The eBPF verifier enforces strict memory bounds. For writes ≥ 1536 bytes, reading the full buffer is impossible. Instead, three 512-byte chunks are captured:
- **Start** (`buf[0..512]`) — file header, often reveals format
- **Middle** (`buf[size/2 - 256 .. size/2 + 256]`) — mid-stream content
- **End** (`buf[size-512 .. size]`) — footer

For writes between 512–1535 bytes, the full content is read (bounded by `n &= 0x7FF` for verifier compliance).

**Ring buffer**: 16MB (`1 << 24`). Events are submitted with `bpf_ringbuf_submit` — if the buffer is full, events are dropped silently.

**Event structure:**

```c
struct event_t {
    u32 pid;
    u32 size;       // full write size as reported by the kernel
    u32 copied;     // how many bytes actually sampled (≤ 1536)
    char comm[16];  // process name
    char fname[32]; // filename (from dentry, not full path)
    u8 data[1536];  // sampled payload
};
```

---

### 2. Reader Goroutine (`main.go`)

Drains the eBPF ring buffer in a tight loop via `cilium/ebpf/ringbuf`. Each raw record is pushed onto `eventsChan` (capacity 10,000). On ring buffer close (shutdown), it closes `eventsChan` to propagate the stop signal downstream.

---

### 3. Worker Goroutines (`worker()`, 4 instances)

Each worker:
1. Deserializes raw bytes into `bpf.BpfEventT` via unsafe pointer cast (zero-copy)
2. Calls `calculateFastEntropy()` on `event.Data[:event.Copied]`
3. Emits an `UpdatePayload` with `IsEnc: ent >= 7.5` onto `updatesChan`

**Entropy calculation:**

Shannon entropy is computed using a precomputed LUT (`entropyLUT`) that stores `count * log2(count)` for all counts 0–1536. This avoids repeated `math.Log2` calls in the hot path.

```
H = log2(N) - (Σ count[b] * log2(count[b])) / N
```

Score range: 0.0 (all same byte) to 8.0 (perfectly uniform). AES ciphertext reliably scores ≥ 7.9.

---

### 4. Stats Aggregator (`statsAggregator()`)

Single goroutine, owns the `stats map[uint32]*ProcessStats` under a `sync.RWMutex`.

**Per-PID accounting:**

```go
type ProcessStats struct {
    Comm       string
    BytesTotal uint64   // all VFS write bytes seen
    BytesEnc   uint64   // bytes where entropy >= 7.5
    LastFile   string
    LastSeen   time.Time
    Alerted    bool
}
```

**Alert gate (daemon mode only):**

```
BytesEnc > 1,000,000 bytes  (1MB cumulative high-entropy)
    AND
BytesEnc / BytesTotal >= 0.70  (70% of writes are high-entropy)
    AND
!s.Alerted  (one alert per PID)
```

The two-gate design is specifically to avoid false positives from benign tools. A gzip run writes high-entropy data but typically doesn't sustain 70% of its total I/O as ciphertext over 1MB.

**GC ticker**: every 30 seconds, any PID not seen in the last 2 minutes is evicted from the map. This prevents unbounded memory growth.

---

### 5. Output Modes

**TUI mode (default):** Bubble Tea terminal UI, refreshes every 2 seconds. Shows the top 20 PIDs sorted by encrypted MB. Columns: PID, process name, total MB written, encrypted MB, encryption ratio %, last filename touched.

**Daemon mode (`--daemon`):** No TUI. Runs as a systemd service. Alerts logged via `log.Printf` to stdout/journal. Managed via `systemctl status rekd`.

---

### 6. Shutdown Sequence

```
Ctrl+C / SIGTERM
    → context cancels
    → rd.Close() (ring buffer)
    → reader goroutine exits → eventsChan closed
    → worker goroutines drain and exit → updatesChan closed
    → stats aggregator drains and exits
    → TUI gets p.Quit() / daemon exits <-ctx.Done()
```

WaitGroups ensure all goroutines flush before the process exits.

---

## Test Suite

**`tests/dummy_ransomware/main.go`** — AES-CTR file encryptor

- Walks a target directory, encrypts every eligible file in-place
- Uses a 4096-byte write buffer (strictly enforced via `ProxyWriter`/`ProxyReader` to prevent `io.Copy` from optimizing away the syscalls)
- Prepends a random 16-byte IV to each encrypted file
- Key stored in `thekey.key` (32 bytes, generated on first run)
- This 4KB buffer size is intentional: it triggers rekd's 512-byte threshold repeatedly and stays well above it

**`tests/run_tests/run_tests.sh`** — automated integration test

1. Generates fresh test data: 100×100KB + 50×2MB random files
2. Starts rekd in daemon mode, waits 2s for init
3. Runs the dummy ransomware encryptor against the test data
4. Waits 2s for log flush, kills rekd
5. Checks logs for `"High Entropy Write Detected"` and reports pass/fail

---

## Known Blind Spots

These are documented in the README and are real architectural limitations:

| Gap | Impact | Notes |
|-----|--------|-------|
| `vfs_writev` not hooked | Akira, and likely other advanced ransomware, uses vectorized I/O (`pwritev`) to pass multiple buffers in one syscall. This entirely bypasses rekd. | Adding `vfs_writev` support requires handling scattered `iov` vectors, which is significantly more complex in eBPF |
| One alert per PID | If a process pauses and resumes encryption (e.g., after a network round-trip), no second alert fires | `s.Alerted` is never reset |
| Scattered sampling | For large writes, only 3×512B of potentially MBs of data is analyzed. A ransomware variant that front-loads plaintext headers could score below threshold | Hard constraint from eBPF verifier memory limits |
| Entropy splitting | Future variants could split ciphertext across multiple passes to keep per-write entropy around 5.0, below the 7.5 threshold | Would require time-windowed correlation across writes |
| No persistent state | Stats are in-memory only. A rekd restart loses all accumulated per-PID history | A process that encrypts slowly across a restart window would reset its 1MB gate |
| fname is not a full path | Only the dentry filename (last component) is captured, not the full path. `document.docx` vs `/home/user/work/document.docx` | BTF full-path resolution from dentry chains is expensive in eBPF |
| Silent ring buffer drops | If the 16MB ring buffer fills (e.g., during a burst), events are silently discarded. No back-pressure mechanism exists | Could be partially mitigated by monitoring the ring buffer's `lost` counter |

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/cilium/ebpf` | BPF object loading, ring buffer reader, fentry attachment (pure Go, no CGo) |
| `github.com/charmbracelet/bubbletea` | TUI event loop (Elm architecture) |
| `github.com/charmbracelet/bubbles` | Table widget |
| `github.com/charmbracelet/lipgloss` | Terminal styling |

All dependencies are pure Go. `CGO_ENABLED=0` produces a fully static binary.

---

## File Map

```
rekd/
├── cmd/rekd/
│   └── main.go          — userspace logic: workers, aggregator, TUI, startup checks
├── internal/bpf/
│   ├── main.bpf.c       — eBPF C program (CO-RE, uses vmlinux.h + BPF_CORE_READ)
│   ├── generate.go      — //go:generate directive for bpf2go
│   ├── bpf_bpfel.o      — compiled BPF object, little-endian (committed to git)
│   ├── bpf_bpfeb.o      — compiled BPF object, big-endian (committed to git)
│   ├── bpf_bpfel.go     — generated Go bindings + //go:embed for bpf_bpfel.o
│   ├── bpf_bpfeb.go     — generated Go bindings + //go:embed for bpf_bpfeb.o
│   └── vmlinux.h        — kernel BTF header (CO-RE; no kernel headers at runtime)
├── tests/
│   ├── dummy_ransomware/
│   │   └── main.go      — AES-CTR encryptor for testing
│   └── run_tests/
│       └── run_tests.sh — integration test script
├── poc/python/
│   └── scanner.py       — original Python POC (archived, >6% CPU overhead)
├── scripts/
│   ├── install.sh       — preflight checks, optional build, systemd registration
│   └── uninstall.sh     — removes service and binary
├── Makefile             — build / generate / install / clean targets
└── docs/
    └── ARCHITECTURE.md  — this file
```
