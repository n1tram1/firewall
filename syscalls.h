#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags);

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size);

#endif /* ! SYSCALLS_H */
