#include "bpf_program.h"

#include <stdlib.h>

struct bpf_program *bpf_program_new(void)
{
	struct bpf_program *prog;

	prog = calloc(1, sizeof(*prog));
	if (!prog)
		return NULL;

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
		reallocarray(prog->instructions, prog->instructions + cnt,
			     sizeof(*prog->instructions));
	if (!prog->instructions)
		return -1;

	memcpy(prog->instructions + prog->instructions, insns, cnt);

	prog->instructions_cnt += cnt;

	return 0;
}
