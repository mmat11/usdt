#define BPF_MAP_TYPE_RINGBUF 27
#define SIZE 100 + 1

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u32 __wsum;

#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
    char filename[SIZE];
    char fn_name[SIZE];
    __s32 lineno;
};

const struct event *unused __attribute__((unused));

SEC("uprobe/python/function__entry")
int handler(struct pt_regs *ctx) {
    // https://docs.python.org/3/howto/instrumentation.html#available-static-markers
    //
    // Displaying notes found in: .note.stapsdt
    // Owner                Data size 	Description
    // stapsdt              0x00000045	NT_STAPSDT (SystemTap probe descriptors)
    // Provider: python
    // Name: function__entry
    // Location: 0x0000000000064f80, Base: 0x00000000002b4f88, Semaphore: 0x000000000034bbd6
    // Arguments: 8@%r14 8@%r15 -4@%eax

    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!ev)
        return 0;

    bpf_probe_read_user_str(ev->filename, SIZE, (void *)ctx->r14);
    bpf_probe_read_user_str(ev->fn_name, SIZE, (void *)ctx->r15);
    ev->lineno = ctx->ax;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
