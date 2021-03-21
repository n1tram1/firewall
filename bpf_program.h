#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include "bpf_insn.h"

struct bpf_program {
	struct bpf_insn instructions;
	size_t instructions_cnt;
};

struct bpf_program *bpf_program_new(void);
void bpf_program_del(struct bpf_program *prog);

int bpf_program_add_instructions(struct bpf_program *prog,
				 const struct bpf_insn *insns, size_t cnt);

#endif /* ! BPF_PROGRAM_H */
