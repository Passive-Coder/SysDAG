// CO-RE-free raw-syscall collector. Build with:
// clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c sysdag.bpf.c -o sysdag.bpf.o
//
// The program correlates raw_syscalls:sys_enter/sys_exit in a bounded per-TID
// map, then submits one compact record to the ring buffer on syscall exit.
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

struct sys_enter_ctx { __u64 _pad; __s64 nr; __u64 args[6]; };
struct sys_exit_ctx { __u64 _pad; __s64 nr; __s64 ret; };
struct syscall_event {
    __u32 tid;
    __u32 tgid;
    __u64 enter_ns;
    __u64 exit_ns;
    __s64 nr;
    __s64 ret;
    __u64 args[3];
};

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32768); } ENTER SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 24); } EVENTS SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1); } DROPS SEC(".maps");

static __inline void count_drop(void) {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&DROPS, &key);
    if (value) __sync_fetch_and_add(value, 1);
    else { __u64 one = 1; bpf_map_update_elem(&DROPS, &key, &one, BPF_ANY); }
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sysdag_enter(struct sys_enter_ctx *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct syscall_event event = {};
    event.tid = tid;
    event.tgid = pid_tgid >> 32;
    event.enter_ns = bpf_ktime_get_ns();
    event.nr = ctx->nr;
    event.args[0] = ctx->args[0]; event.args[1] = ctx->args[1]; event.args[2] = ctx->args[2];
    if (bpf_map_update_elem(&ENTER, &tid, &event, BPF_ANY) < 0) count_drop();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sysdag_exit(struct sys_exit_ctx *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct syscall_event *entered = bpf_map_lookup_elem(&ENTER, &tid);
    if (!entered) { count_drop(); return 0; }
    struct syscall_event *out = bpf_ringbuf_reserve(&EVENTS, sizeof(*out), 0);
    if (!out) { count_drop(); return 0; }
    *out = *entered;
    out->exit_ns = bpf_ktime_get_ns();
    out->ret = ctx->ret;
    bpf_ringbuf_submit(out, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
