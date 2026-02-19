//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COPY 1536 // 3 chunks of 512 bytes
#define CHUNK_SIZE 512
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
    __type(value, struct event_t); //  It forces Clang to keep the BTF!
} events SEC(".maps");

// fentry is fundamentally faster than kprobe because it uses BPF trampolines
// to patch a direct call, avoiding costly context switches and software breakpoints.
SEC("fentry/vfs_write")
int BPF_PROG(vfs_write_fentry, struct file *f, const char *buf, size_t count) {
    u64 size_arg = (u64)count;
    
    // 1. Threshold filter
    if (size_arg < KERNEL_SIZE_THRESHOLD)
        return 0;

    // 2. Regular file filter
    struct inode *i = BPF_CORE_READ(f, f_inode);
    umode_t mode = BPF_CORE_READ(i, i_mode);
    if ((mode & 0xF000) != 0x8000) 
        return 0;

    // 3. Reserve buffer space immediately
    struct event_t *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // 4. Gather Metadata
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->size = size_arg;
    e->copied = 0;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Safely read the filename using BTF core reads
    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    const unsigned char *name_ptr = BPF_CORE_READ(d, d_name.name);
    bpf_probe_read_kernel_str(&e->fname, sizeof(e->fname), name_ptr);

    // 5. Scattered Read Payload - VERIFIER SAFE METHOD
    if (size_arg >= MAX_COPY) {
        // Start chunk
        bpf_probe_read_user(&e->data[0], CHUNK_SIZE, buf);
        
        // Middle chunk (calculated offset)
        u64 mid_offset = (size_arg / 2) - (CHUNK_SIZE / 2);
        bpf_probe_read_user(&e->data[CHUNK_SIZE], CHUNK_SIZE, buf + mid_offset);
        
        // End chunk (calculated offset)
        u64 end_offset = size_arg - CHUNK_SIZE;
        bpf_probe_read_user(&e->data[CHUNK_SIZE * 2], CHUNK_SIZE, buf + end_offset);
        
        e->copied = MAX_COPY;
    } else {
        // If the write is between 512 and 1536 bytes, read up to what we safely can
        u32 n = (u32)size_arg;
        if (n > MAX_COPY) n = MAX_COPY; 
        
        // The verifier requires strict bounding for dynamic read lengths
        n &= 0x7FF; 
        bpf_probe_read_user(&e->data[0], n, buf);
        e->copied = n;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}