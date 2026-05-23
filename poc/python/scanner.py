from bcc import BPF
import ctypes, time, signal, os, math, shutil, sys, argparse
from collections import defaultdict, deque
from contextlib import contextmanager
from rich.live import Live
from rich.table import Table
from rich import box
import yaml 

# ======= CONFIG DEFAULTS =======
KERNEL_SIZE_THRESHOLD = 512
MAX_COPY = 4096
ENTROPY_THRESHOLD = 7.5
ENC_RATIO_GATE = 0.7
ENC_CUMULATIVE_GATE = 1 * 1024 * 1024
WINDOW_SEC = 3
FPS = 15
MAGIC = [b'\x50\x4b\x03\x04', b'\x1f\x8b', b'\x89PNG', b'\xff\xd8\xff']
DEFAULT_CONFIG_FILE = "exclusions.yaml"

# ======= SAMPLE CONFIG =======
SAMPLE_YAML = """exclusions:
  - "code"
  - "slack"
  - "spotify"
  - "firefox"
  - "chrome"
"""

# ======= ARGUMENTS =======
def parse_args():
    p = argparse.ArgumentParser(description="vfs_write encrypted-IO scanner (regular files only)")
    p.add_argument("--init-config", action="store_true", help="Generate exclusions.yaml")
    p.add_argument("--config", default=DEFAULT_CONFIG_FILE, help="Path to config file")
    p.add_argument("--log", help="Path to CSV log file")
    # Added Daemon flag
    p.add_argument("--daemon", action="store_true", help="Run in background/headless mode (no UI)")
    return p.parse_args()

def load_exclusions(path):
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return set(data.get("exclusions", []))

@contextmanager
def quiet():
    fd = os.dup(1)
    dn = os.open(os.devnull, os.O_WRONLY)
    os.dup2(dn, 1)
    try:
        yield
    finally:
        os.dup2(fd, 1)
        os.close(fd); os.close(dn)

# ======= BPF PROGRAM =======
bpf_text = f"""
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/stat.h>

#define MAX_COPY {MAX_COPY}

struct event_t {{
    u32 pid, size, copied;
    char comm[16];
    char fname[32];
    unsigned char data[MAX_COPY];
}};

BPF_RINGBUF_OUTPUT(events, 1024);
BPF_ARRAY(thr, u32, 1);

int kprobe__vfs_write(struct pt_regs *ctx)
{{
    struct file *f = (void *)PT_REGS_PARM1(ctx);
    const char __user *buf = (void *)PT_REGS_PARM2(ctx);
    size_t cnt = PT_REGS_PARM3(ctx);

    /* --- FILTER NON-REGULAR FILES --- */
    struct inode *inode = NULL;
    unsigned short mode = 0;

    bpf_probe_read_kernel(&inode, sizeof(inode), &f->f_inode);
    if (!inode)
        return 0;

    bpf_probe_read_kernel(&mode, sizeof(mode), &inode->i_mode);
    if ((mode & S_IFMT) != S_IFREG)
        return 0;

    u32 idx = 0;
    u32 *thr_val = thr.lookup(&idx);
    if (cnt < (thr_val ? *thr_val : {KERNEL_SIZE_THRESHOLD}))
        return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->size = cnt > 0xffffffff ? 0xffffffff : cnt;
    e->copied = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct dentry *d = NULL;
    bpf_probe_read_kernel(&d, sizeof(d), &f->f_path.dentry);
    if (d) {{
        struct qstr q;
        bpf_probe_read_kernel(&q, sizeof(q), &d->d_name);
        bpf_probe_read_kernel_str(e->fname, sizeof(e->fname), q.name);
    }}

    u32 n = cnt > MAX_COPY ? MAX_COPY : cnt;
    if (n && !bpf_probe_read_user(e->data, n, buf))
        e->copied = n;

    events.ringbuf_submit(e, 0);
    return 0;
}}
"""

# ======= USER SPACE STRUCT =======
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("size", ctypes.c_uint),
        ("copied", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),
        ("fname", ctypes.c_char * 32),
        ("data", ctypes.c_ubyte * MAX_COPY),
    ]

# ======= HELPERS =======
def entropy(b):
    if not b or any(b.startswith(m) for m in MAGIC):
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    l = len(b)
    return sum(-(c/l) * math.log2(c/l) for c in freq if c)

# ======= STATE =======
running = True
start_time = time.time()
events_total = 0
bytes_total = 0

bytes_per_pid = defaultdict(int)
sampled_cum_per_pid = defaultdict(int)
enc_cum_per_pid = defaultdict(int)
comm_per_pid = {}
lastfile_per_pid = {}

EXCLUDED_COMMS = set()
LOG_HANDLE = None

def stop(*_):
    global running
    running = False

signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)

# ======= RINGBUF HANDLER =======
def handle(_, data, __):
    global events_total, bytes_total
    e = ctypes.cast(data, ctypes.POINTER(Event)).contents

    comm = e.comm.decode(errors="replace").rstrip("\x00")
    if comm in EXCLUDED_COMMS:
        return

    pid = e.pid
    fname = e.fname.decode(errors="replace").rstrip("\x00")
    sz = e.size

    ent = 0.0
    is_enc = False
    if e.copied:
        payload = bytes(e.data[:e.copied])
        ent = entropy(payload)
        is_enc = ent >= ENTROPY_THRESHOLD

    if LOG_HANDLE:
        try:
            LOG_HANDLE.write(
                f"{time.time()},{pid},{comm},{fname},{sz},{ent:.4f},{int(is_enc)}\n"
            )
        except:
            pass

    # We still track stats in daemon mode, though we don't display them
    events_total += 1
    bytes_total += sz
    bytes_per_pid[pid] += sz
    comm_per_pid[pid] = comm
    if fname:
        lastfile_per_pid[pid] = fname
    if e.copied:
        sampled_cum_per_pid[pid] += e.copied
        if is_enc:
            enc_cum_per_pid[pid] += e.copied

# ======= UI =======
def render():
    t = Table(title="vfs_write encrypted disk IO", box=box.MINIMAL_DOUBLE_HEAD)
    t.add_column("PID", justify="right")
    t.add_column("COMM")
    t.add_column("Total MB", justify="right")
    t.add_column("Enc MB", justify="right")
    t.add_column("Enc %", justify="right")
    t.add_column("Last File")

    for pid in sorted(bytes_per_pid, key=lambda p: enc_cum_per_pid[p], reverse=True):
        sampled = sampled_cum_per_pid[pid]
        enc = enc_cum_per_pid[pid]
        ratio = enc / sampled if sampled else 0
        style = "bold red" if ratio >= ENC_RATIO_GATE and enc >= ENC_CUMULATIVE_GATE else ""
        t.add_row(
            str(pid),
            comm_per_pid.get(pid, "?"),
            f"{bytes_per_pid[pid]/1e6:.2f}",
            f"{enc/1e6:.2f}",
            f"{ratio*100:.1f}",
            lastfile_per_pid.get(pid, "-"),
            style=style
        )

    t.caption = f"events={events_total} bytes={bytes_total/1e6:.1f}MB"
    return t

# ======= MAIN =======
if __name__ == "__main__":
    args = parse_args()

    # --init-config
    if args.init_config:
        with open(DEFAULT_CONFIG_FILE, "w") as f:
            f.write(SAMPLE_YAML)
        sys.exit(0)

    # --config
    EXCLUDED_COMMS = load_exclusions(args.config)

    # --log
    if args.log:
        try:
            LOG_HANDLE = open(args.log, "w", buffering=1)
            LOG_HANDLE.write("ts,pid,comm,file,size,entropy,is_enc\n")
            if not args.daemon:
                print(f"[*] Logging enabled: {args.log}")
        except Exception as e:
            print(f"[!] Error opening log: {e}")
            sys.exit(1)
    elif args.daemon:
        print("[!] Warning: Daemon mode running without logging.")

    if not args.daemon:
        print("[*] Loading BPF...")

    # Load BPF (using quiet to suppress BCC boilerplate output)
    with quiet():
        b = BPF(text=bpf_text)

    b["thr"][ctypes.c_uint(0)] = ctypes.c_uint(KERNEL_SIZE_THRESHOLD)
    b["events"].open_ring_buffer(handle)

    # MAIN LOOP
    if args.daemon:
        # Headless mode: Simple loop, no UI
        print(f"[*] Daemon started. PID: {os.getpid()}")
        try:
            while running:
                b.ring_buffer_poll(100)
        except KeyboardInterrupt:
            pass
    else:
        # UI mode: Rich Table
        print("[*] Running (Ctrl+C to stop)")
        try:
            with Live(render(), refresh_per_second=FPS) as live:
                while running:
                    b.ring_buffer_poll(100)
                    live.update(render())
        except KeyboardInterrupt:
            pass

    if LOG_HANDLE:
        LOG_HANDLE.close()
        print(f"[*] Log saved to {args.log}")