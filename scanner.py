from bcc import BPF
import ctypes, time, signal, os, math, shutil
from collections import defaultdict, deque
from contextlib import contextmanager
from rich.live import Live
from rich.table import Table
from rich import box

# ======= CONFIG =======
KERNEL_SIZE_THRESHOLD = 512
MAX_COPY = 4096
ENTROPY_THRESHOLD = 7.5
ENC_RATIO_GATE = 0.7            # fraction (70%)
ENC_CUMULATIVE_GATE = 1 * 1024*1024  # 1 MB cumulative encrypted sampled
WINDOW_SEC = 3
FPS = 15
MAGIC = [b'\x50\x4b\x03\x04', b'\x1f\x8b', b'\x89PNG', b'\xff\xd8\xff']

# ======= QUIET CONTEXT =======
@contextmanager
def quiet():
    fd = os.dup(1)
    dn = os.open(os.devnull, os.O_WRONLY)
    os.dup2(dn, 1)
    try:
        yield
    finally:
        os.dup2(fd, 1)
        os.close(dn); os.close(fd)

# ======= BPF PROGRAM =======
bpf_text = f"""
#include <linux/fs.h>
#include <linux/dcache.h>
#define MAX_COPY {MAX_COPY}

struct event_t {{
    u32 pid, size, copied;
    char comm[16], fname[32];
    unsigned char data[MAX_COPY];
}};

BPF_RINGBUF_OUTPUT(events, 1024);
BPF_ARRAY(thr, u32, 1);

int kprobe__vfs_write(struct pt_regs *ctx) {{
    struct file *f = (void*)PT_REGS_PARM1(ctx);
    const char __user *buf = (void*)PT_REGS_PARM2(ctx);
    size_t cnt = PT_REGS_PARM3(ctx);
    u32 i=0, *t = thr.lookup(&i);
    if (cnt < (t ? *t : {KERNEL_SIZE_THRESHOLD})) return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return 0;
    e->copied = 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->size = cnt > 0xffffffff ? 0xffffffff : cnt;
    bpf_get_current_comm(&e->comm, 16);

    struct dentry *d = 0;
    bpf_probe_read_kernel(&d, sizeof(d), &f->f_path.dentry);
    if (d) {{
        struct qstr q;
        bpf_probe_read_kernel(&q, sizeof(q), &d->d_name);
        bpf_probe_read_kernel_str(e->fname, 32, q.name);
    }}

    u32 n = cnt > MAX_COPY ? MAX_COPY : cnt;
    if (n && !bpf_probe_read_user(e->data, n, buf)) e->copied = n;
    events.ringbuf_submit(e, 0);
    return 0;
}}
"""

# ======= USER-SPACE STRUCT =======
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
def entropy(b: bytes) -> float:
    if not b or any(b.startswith(m) for m in MAGIC): return 0.0
    freq = [0]*256
    for x in b: freq[x]+=1
    l = len(b)
    return sum(-(c/l)*math.log2(c/l) for c in freq if c)

def max_rows():
    h = shutil.get_terminal_size((120, 40)).lines
    return max(5, h - 8)

# ======= STATE =======
running = True
start_time = time.time()
events_total = 0
bytes_total = 0

bytes_per_pid = defaultdict(int)
events_per_pid = defaultdict(int)
comm_per_pid = {}
lastfile_per_pid = {}

# per-PID cumulative sampled and encrypted sampled totals (user asked)
sampled_cum_per_pid = defaultdict(int)
enc_cum_per_pid = defaultdict(int)

# per-PID recent buckets (time bucketing per PID kept for future rate work)
buckets = defaultdict(lambda: deque(maxlen=WINDOW_SEC))

# ======= SIGNALS =======
def _stop(*_): 
    global running
    running = False
signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)

# ======= RINGBUF HANDLER =======
def handle(_, data, __):
    global events_total, bytes_total
    e = ctypes.cast(data, ctypes.POINTER(Event)).contents
    pid = e.pid
    sz = e.size
    comm = e.comm.decode("utf-8", "replace").rstrip("\x00")
    fname = e.fname.decode("utf-8", "replace").rstrip("\x00")

    events_total += 1
    bytes_total += sz

    bytes_per_pid[pid] += sz
    events_per_pid[pid] += 1
    comm_per_pid[pid] = comm
    if fname:
        lastfile_per_pid[pid] = fname

    if e.copied:
        payload = bytes(e.data[:e.copied])
        sampled_cum_per_pid[pid] += e.copied
        ent = entropy(payload)
        is_enc = ent >= ENTROPY_THRESHOLD
        if is_enc:
            enc_cum_per_pid[pid] += e.copied
        # time bucket for PID (timestamp, bytes, enc_flag)
        buckets[pid].append((time.time(), e.copied, is_enc))

# ======= UI (Rich) =======
def render_table():
    t = Table(title="vfs_write encrypted-IO telemetry", box=box.MINIMAL_DOUBLE_HEAD, expand=True)
    t.add_column("PID", justify="right")
    t.add_column("COMM", justify="left")
    t.add_column("Total MB", justify="right")
    t.add_column("Enc MB (cum)", justify="right")
    t.add_column("Enc %", justify="right")
    t.add_column("Last File", justify="left")

    # sort by cumulative encrypted sampled bytes descending, then total bytes
    rows = sorted(bytes_per_pid.keys(), key=lambda p: (enc_cum_per_pid[p], bytes_per_pid[p]), reverse=True)
    for pid in rows[:max_rows()]:
        total_mb = bytes_per_pid[pid] / 1e6
        enc_mb = enc_cum_per_pid[pid] / 1e6
        sampled = sampled_cum_per_pid[pid]
        enc = enc_cum_per_pid[pid]
        ratio = (enc / sampled) if sampled else 0.0
        style = "bold red" if (ratio >= ENC_RATIO_GATE and enc >= ENC_CUMULATIVE_GATE) else ""
        t.add_row(
            str(pid),
            comm_per_pid.get(pid, "?"),
            f"{total_mb:7.2f}",
            f"{enc_mb:7.3f}",
            f"{ratio*100:5.1f}",
            lastfile_per_pid.get(pid, "-"),
            style=style
        )

    rt = time.time() - start_time
    t.caption = f"events={events_total}  bytes={bytes_total/1e6:.1f}MB  runtime={rt:.1f}s"
    return t

# ======= MAIN =======
if __name__ == "__main__":
    print("[*] Loading BPF (quiet)...")
    with quiet():
        b = BPF(text=bpf_text, cflags=[
            "-Wno-duplicate-decl-specifier",
            "-Wno-macro-redefined",
            "-Wno-address-of-packed-member"
        ])
    # set kernel threshold
    b["thr"][ctypes.c_uint(0)] = ctypes.c_uint(KERNEL_SIZE_THRESHOLD)
    b["events"].open_ring_buffer(handle)

    print("[*] Running (Ctrl+C to stop)")
    with Live(render_table(), refresh_per_second=FPS) as live:
        while running:
            try:
                b.ring_buffer_poll(timeout=100)
            except Exception:
                pass
            live.update(render_table())
