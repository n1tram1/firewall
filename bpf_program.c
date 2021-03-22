#include "bpf_program.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <err.h>

#include "utils.h"

struct bpf_program *bpf_program_new(uint32_t prog_type)
{
	struct bpf_program *prog;

	prog = calloc(1, sizeof(*prog));
	if (!prog)
		return NULL;

	prog->fd = -1;
	prog->type = prog_type;

	return prog;
}

void bpf_program_del(struct bpf_program *prog)
{
	free(prog->instructions);
	free(prog);
}

int bpf_program_add_instructions(struct bpf_program *prog,
				 const struct bpf_insn *insns, size_t cnt)
{
	prog->instructions =
		reallocarray(prog->instructions, prog->instructions_cnt + cnt,
			     sizeof(*prog->instructions));
	if (!prog->instructions)
		return -1;

	memcpy(prog->instructions + prog->instructions_cnt, insns, cnt * sizeof(*prog->instructions));

	prog->instructions_cnt += cnt;

	return 0;
}

#include "bpf_insn.h"

int bpf_program_load(struct bpf_program *prog)
{
	union bpf_attr attr;
	char logbuf[4096];

	memset(&attr, 0, sizeof(attr));

	attr.prog_type = prog->type;
	attr.insns = ptr_to_u64(prog->instructions);
	attr.insn_cnt = prog->instructions_cnt;
	attr.license = ptr_to_u64("GPL");
	attr.log_buf = ptr_to_u64(logbuf);
	attr.log_size = array_len(logbuf);
	attr.log_level = 1;

	prog->fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if (prog->fd < 0) {
		warn("bpf(BPF_PROG_LOAD...)\nVerifier log:\n%s\n---", logbuf);
		return -1;
	}

	return 0;
}

int bpf_program_cgroup_attach(struct bpf_program *prog, int type, const char *path, uint32_t flags)
{
	union bpf_attr attr;
	int fd;

	fd = open(path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	memset(&attr, 0, sizeof(attr));

	attr.attach_type = type;
	attr.target_fd = fd;
	attr.attach_bpf_fd = prog->fd;
	attr.attach_flags = flags;

	if (bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0) {
		warn("bpf(BPF_PROG_ATTACH...");
		return -1;
	}

	return 0;
}
