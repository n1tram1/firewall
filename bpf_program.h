#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/bpf.h>
#include <stdlib.h>
#include <stdint.h>

struct bpf_program {
	struct bpf_insn *instructions;
	size_t instructions_cnt;

    uint32_t type; // BPF program type

    int fd;
};

struct bpf_program *bpf_program_new(uint32_t prog_type);
void bpf_program_del(struct bpf_program *prog);

int bpf_program_add_instructions(struct bpf_program *prog,
				 const struct bpf_insn *insns, size_t cnt);

int bpf_program_load(struct bpf_program *prog);
int bpf_program_cgroup_attach(struct bpf_program *prog, int type, const char *path, uint32_t flags);

#endif /* ! BPF_PROGRAM_H */
