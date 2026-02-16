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
    u64 size_arg = (u64)cnt;
    
    // 1. Threshold filter
    if (size_arg < KERNEL_SIZE_THRESHOLD)
        return 0;

    // 2. Regular file filter
    struct inode *i = BPF_CORE_READ(f, f_inode);
    umode_t mode = BPF_CORE_READ(i, i_mode);
    if ((mode & 0xF000) != 0x8000) 
        return 0;

    // 3. Reserve buffer
    struct event_t *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // 4. Metadata
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->size = size_arg;
    e->copied = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    const unsigned char *name_ptr = BPF_CORE_READ(d, d_name.name);
    bpf_probe_read_str(&e->fname, sizeof(e->fname), name_ptr);

    // 5. Read Payload - VERIFIER SAFE METHOD
    u32 n = (u32)size_arg;

    // Logic: Clamp to 4095. 
    // We use 4095 (0xFFF) instead of 4096 to allow using a clean bitmask.
    if (n > 4095) {
        n = 4095;
    }

    // MANDATORY for Verifier: 'n' must be bitwise-ANDed with a constant 
    // to prove it cannot be negative or overflow.
    n &= 0xFFF; 

    // Now 'n' is guaranteed to be [0..4095], which fits in data[4096].
    long ret = bpf_probe_read_user(&e->data, n, buf);
    if (ret == 0) {
        e->copied = n;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
