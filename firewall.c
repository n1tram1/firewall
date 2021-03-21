#include <err.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>

#include "bpf_insn.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

#define array_len(ARR) (sizeof(ARR) / sizeof(*(ARR)))
#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd,
		      flags);
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

struct options {
	enum {
		BLOCK,
		ACCEPT,
	} action;

	uint32_t source;
	uint16_t sport;

	uint32_t destination;
	uint16_t dport;
};

static int parse_argv(char **argv, struct options *opts)
{
	if (!strcmp(argv[1], "block")) {
		opts->action = BLOCK;
	} else if (!strcmp(argv[1], "accept")) {
		opts->action = ACCEPT;
	} else {
		warnx("invalid action %s, expected <action|block>", argv[1]);
		return -1;
	}

	if (inet_pton(AF_INET, argv[2], &opts->source) != 1) {
		warn("inet_pton(<source> %s)", argv[2]);
		return -1;
	}

	errno = 0;
	opts->sport = strtoul(argv[3], NULL, 10);
	if (errno) {
		warn("strtoul(<sport> %s)", argv[3]);
		return -1;
	}

	if (inet_pton(AF_INET, argv[4], &opts->destination) != 1) {
		warn("inet_pton(<destination> %s)", argv[4]);
		return -1;
	}

	errno = 0;
	opts->dport = strtoul(argv[5], NULL, 10);
	if (errno) {
		warn("strtoul(<dport> %s)", argv[5]);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct options opts;
	struct bpf_program *prog;

	if (argc != 6)
		errx(EXIT_FAILURE,
		     "Usage: %s <block|accept> source sport destination dport",
		     argv[0]);

	if (parse_argv(argv, &opts) < 0)
		exit(EXIT_FAILURE);

	prog = bpf_program_new();

	switch (opts.action) {
	case BLOCK:
		if (bpf_program_add_socket_block_instructions(
			    prog, opts.source, opts.sport, opts.destination,
			    opts.dport) < 0)
			err(EXIT_FAILURE, "failed to build block instructions");
	case ACCEPT:
		// By default the socket is already accepted
		// do nothing...
		errx(EXIT_SUCCESS, "accepting the socket");
	};

	struct bpf_insn instructions[] = {
		// get the comm
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -40),

		BPF_MOV64_IMM(BPF_REG_2, 30),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_get_current_comm),

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

		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_trace_printk),

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
	perf_attr.config =
		699; /* /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/id */
	perf_attr.sample_period = 1;
	perf_attr.wakeup_events = 1;

	int perf_fd =
		perf_event_open(&perf_attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (perf_fd < 0)
		err(1, "perf_event_open");

	ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

	puts(logbuf);
	for (;;)
		; /* read_trace_pipe(); */
}
