// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

struct bpf_raw_tracepoint_args {
    __u64 args[6];
};

SEC("raw_tracepoint/sys_enter")
int handle_raw_tp(struct bpf_raw_tracepoint_args *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    int syscall_nr = ctx->args[1]; // args[1] is syscall number

    // Uncomment to filter by PID
    // if (pid != my_pid)
    //     return 0;

    // Filter: only log write() calls (syscall number varies by arch)
    // For x86_64, write syscall is 1
    if (syscall_nr == 1) {
        bpf_printk("BPF triggered from PID %d on sys_write.\n", pid);
    }

    return 0;
}
