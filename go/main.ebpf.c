//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COPY 4096
#define FILE_NAME_LEN 32
#define COMM_LEN 16
#define KERNEL_SIZE_THRESHOLD 512

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
    u32 pid;
    u32 size;
    u32 copied;
    char comm[COMM_LEN];
    char fname[FILE_NAME_LEN];
    u8 data[MAX_COPY];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB buffer
} events SEC(".maps");

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write, struct file *f, const char *buf, size_t cnt) {
    // 1. Initial Threshold Check
    u64 size_arg = (u64)cnt;
    if (size_arg < KERNEL_SIZE_THRESHOLD)
        return 0;

    // 2. Filter for Regular Files
    struct inode *i = BPF_CORE_READ(f, f_inode);
    umode_t mode = BPF_CORE_READ(i, i_mode);
    if ((mode & 0xF000) != 0x8000) // S_IFREG
        return 0;

    // 3. Reserve Ringbuf
    struct event_t *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // 4. Populate Metadata
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->size = size_arg;
    e->copied = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    const unsigned char *name_ptr = BPF_CORE_READ(d, d_name.name);
    bpf_probe_read_str(&e->fname, sizeof(e->fname), name_ptr);

    // 5. Read User Data Payload (The Tricky Part)
    u32 n = (u32)size_arg;

    // Cap at 4095 bytes (0xFFF).
    // We lose 1 byte of potential data vs 4096, but it satisfies the verifier 
    // because 4095 < 4096 is mathematically proven by the mask.
    if (n > 4095) {
        n = 4095;
    }

    // MANDATORY: Bitwise AND with a constant.
    // This tells the verifier: "Whatever n
