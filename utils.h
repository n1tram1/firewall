#ifndef UTILS_H
#define UTILS_H

#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <unistd.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"

#define array_len(ARR) (sizeof(ARR) / sizeof(*(ARR)))
#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

inline
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd,
		      flags);
	return ret;
}

inline
static int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

#endif /* ! UTILS_H */
