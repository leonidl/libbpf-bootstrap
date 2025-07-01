#ifndef __MINIMAL_H
#define __MINIMAL_H

struct syscall_event {
    __u32 pid;
    __u32 syscall_nr;
};

#endif
