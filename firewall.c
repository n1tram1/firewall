#include <err.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <endian.h>
#include <fcntl.h>
#include <asm/unistd.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <signal.h>

#include "bpf_insn.h"

#include "bpf_program.h"
#include "utils.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	static char buf[4096];
	ssize_t sz;

	sz = read(trace_fd, buf, sizeof(buf) - 1);
	if (sz > 0) {
		buf[sz] = 0;
		puts(buf);
	}

	close(trace_fd);
}

volatile sig_atomic_t stop = false;

static void sigint_handler(int signum)
{
	(void)signum;

	stop = true;
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

static int add_socket_block_instructions(struct bpf_program *prog,
					 uint32_t source, uint16_t sport,
					 uint32_t destination, uint16_t dport)
{
	struct bpf_insn instructions[] = {
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
		BPF_ST_MEM(BPF_W, BPF_REG_1, 0, 0x000A7825),
		BPF_MOV64_IMM(BPF_REG_2, 4),
		BPF_MOV64_IMM(BPF_REG_3, (uint32_t) (htobe16(dport) << 16)),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_trace_printk),

		BPF_MOV64_IMM(BPF_REG_0, SK_PASS),

		BPF_JMP_IMM(BPF_JNE, BPF_REG_6, source, 0),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_7, sport, 0),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_8, destination, 0),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_9, htobe32(dport), 0),

		BPF_MOV64_IMM(BPF_REG_0, SK_DROP),
	};

	/* for (size_t i = 0; i < array_len(instructions); i++) { */
	/* 	if ((instructions[i].code & BPF_JMP) && !(instructions[i].code & BPF_CALL)) { */
	/* 		instructions[i].off = array_len(instructions) - i - 1; */
	/* 		printf("fixing instruction [%lu]\n", i); */
	/* 	} */
	/* } */

#define FIX_JMP_OFF(IDX) instructions[IDX].off = array_len(instructions) - IDX - 1;
	FIX_JMP_OFF(7);
	FIX_JMP_OFF(8);
	FIX_JMP_OFF(9);

	if (bpf_program_add_instructions(prog, instructions,
					 array_len(instructions)) < 0)
		return -1;

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

	prog = bpf_program_new(BPF_PROG_TYPE_CGROUP_SKB);

	struct bpf_insn pre_insn[] = {
		BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1, offsetof(struct __sk_buff, local_ip4)),
		BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_1, offsetof(struct __sk_buff, local_port)),
		BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_1, offsetof(struct __sk_buff, remote_ip4)),
		BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_1, offsetof(struct __sk_buff, remote_port)),
	};
	if (bpf_program_add_instructions(prog, pre_insn, array_len(pre_insn)) < 0)
		errx(EXIT_FAILURE, "failed to add pre-instructions");

	switch (opts.action) {
	case BLOCK:
		if (add_socket_block_instructions(prog, opts.source, opts.sport,
						  opts.destination,
						  opts.dport) < 0)
			err(EXIT_FAILURE, "failed to build block instructions");
		break;
	case ACCEPT:
		// By default the socket is already accepted
		// do nothing...
		errx(EXIT_SUCCESS, "accepting the socket");
	};

	struct bpf_insn post_insn[] = {
		BPF_EXIT_INSN(),
	};
	if (bpf_program_add_instructions(prog, post_insn, array_len(post_insn)) < 0)
		errx(EXIT_FAILURE, "failed to add post-instructions");

	if (bpf_program_load(prog) < 0)
		errx(EXIT_FAILURE, "bpf_program_load");

	if (bpf_program_cgroup_attach(prog, BPF_CGROUP_INET_INGRESS,
				      "/sys/fs/cgroup/unified/user.slice/",
				      0) < 0)
		errx(EXIT_FAILURE, "bpf_program_cgroup_attach");

	signal(SIGINT, sigint_handler);

	while (!stop)
		read_trace_pipe();

	bpf_program_cgroup_detach(prog);
	bpf_program_destroy(prog);

	warnx("Detached and destroyed eBPF firewall.");

	return 0;
}
