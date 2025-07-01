// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

struct syscall_event {
    __u32 pid;
    __u32 syscall_nr;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// struct bpf_raw_tracepoint_args {
//     __u64 args[6];
// };

SEC("raw_tracepoint/sys_enter")
int handle_raw_tp(struct bpf_raw_tracepoint_args *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    int syscall_nr = ctx->args[1];

    if (/*pid != my_pid || */syscall_nr != 1)
        return 0;

    struct syscall_event evt = {
        .pid = pid,
        .syscall_nr = syscall_nr,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}
