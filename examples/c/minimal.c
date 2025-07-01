// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <stdlib.h>
#include "minimal.skel.h"
#include "minimal.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct syscall_event *evt = data;
    printf("PID %d made syscall %d\n", evt->pid, evt->syscall_nr);
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct minimal_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);

    skel = minimal_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->bss->my_pid = getpid();

    err = minimal_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // Pin program and map
    // err = bpf_program__pin(skel->progs.handle_raw_tp, "/sys/fs/bpf/myapp/raw_tp_sysenter");
    // if (err) {
    //     fprintf(stderr, "Failed to pin BPF program\n");
    //     goto cleanup;
    // }

    // err = bpf_map__pin(skel->maps.events, "/sys/fs/bpf/myapp/events_map");
    // if (err) {
    //     fprintf(stderr, "Failed to pin BPF map\n");
    //     goto cleanup;
    // }

    // err = minimal_bpf__attach(skel);
    // if (err) {
    //     fprintf(stderr, "Failed to attach BPF skeleton\n");
    //     goto cleanup;
    // }

    // rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    // if (!rb) {
    //     fprintf(stderr, "Failed to create ring buffer\n");
    //     err = 1;
    //     goto cleanup;
    // }

    printf("Successfully started! Ctrl+C to exit.\n");

    // while (!exiting)
    //     ring_buffer__poll(rb, 100);

cleanup:
    // ring_buffer__free(rb);
    minimal_bpf__destroy(skel);
    return err != 0;
}
