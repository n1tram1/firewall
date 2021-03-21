#include <err.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>

#include "bpf_insn.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

#define array_len(ARR) (sizeof(ARR) / sizeof(*(ARR)))
#define ptr_to_u64(ptr)    ((__u64)(unsigned long)(ptr))

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
			group_fd, flags);
	return ret;
}

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	    return syscall(__NR_bpf, cmd, attr, size);
}

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(int argc, char **argv)
{
	struct bpf_insn instructions[] = {
		BPF_ST_MEM(1, BPF_REG_10, -100, 0),
		BPF_ST_MEM(1, BPF_REG_10, -96, 0),
		BPF_ST_MEM(1, BPF_REG_10, -92, 0),
		BPF_ST_MEM(1, BPF_REG_10, -88, 0),
		BPF_ST_MEM(1, BPF_REG_10, -84, 0),
		BPF_ST_MEM(1, BPF_REG_10, -80, 0),
		BPF_ST_MEM(1, BPF_REG_10, -76, 0),
		BPF_ST_MEM(1, BPF_REG_10, -72, 0),
		BPF_ST_MEM(1, BPF_REG_10, -68, 0),
		BPF_ST_MEM(1, BPF_REG_10, -64, 0),
		BPF_ST_MEM(1, BPF_REG_10, -60, 0),
		BPF_ST_MEM(1, BPF_REG_10, -56, 0),
		BPF_ST_MEM(1, BPF_REG_10, -52, 0),
		BPF_ST_MEM(1, BPF_REG_10, -48, 0),
		BPF_ST_MEM(1, BPF_REG_10, -44, 0),
		BPF_ST_MEM(1, BPF_REG_10, -40, 0),
		BPF_ST_MEM(1, BPF_REG_10, -36, 0),
		BPF_ST_MEM(1, BPF_REG_10, -32, 0),
		BPF_ST_MEM(1, BPF_REG_10, -28, 0),
		BPF_ST_MEM(1, BPF_REG_10, -24, 0),
		BPF_ST_MEM(1, BPF_REG_10, -20, 0),
		BPF_ST_MEM(1, BPF_REG_10, -16, 0),
		BPF_ST_MEM(1, BPF_REG_10, -12, 0),
		BPF_ST_MEM(1, BPF_REG_10, -8, 0),
		BPF_ST_MEM(1, BPF_REG_10, -4, 0),

		// get the comm
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -40),

		BPF_MOV64_IMM(BPF_REG_2, 30),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_current_comm),

		// build the fmt "%s\n" in [r1]
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),

		BPF_ST_MEM(32, BPF_REG_10, -8, 0x22732522),
		BPF_ST_MEM(32, BPF_REG_10, -4, 0x00000000),

		// set fmt_len in r2
		BPF_MOV64_IMM(BPF_REG_2, 5),
		//
		// put the comm in r3
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -40),


		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_trace_printk),

		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	char logbuf[1 << 20] = { 0 };

	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
	attr.insns = ptr_to_u64(instructions);
	attr.insn_cnt = array_len(instructions);
	attr.license = ptr_to_u64("GPL");
	attr.log_buf = ptr_to_u64(logbuf);
	attr.log_size = sizeof(logbuf);
	attr.log_level = 2;

	int prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (prog_fd < 0)
		err(1, "bpf\n%s\n", logbuf);

	struct perf_event_attr perf_attr;
	memset(&perf_attr, 0, sizeof(perf_attr));

	perf_attr.type = PERF_TYPE_TRACEPOINT;
	perf_attr.size = sizeof(perf_attr);
	perf_attr.config = 699; /* /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/id */
	perf_attr.sample_period = 1;
	perf_attr.wakeup_events = 1;

	int perf_fd = perf_event_open(&perf_attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (perf_fd < 0)
		err(1, "perf_event_open");

	ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

	puts(logbuf);
	for (;;)
		;/* read_trace_pipe(); */
}
