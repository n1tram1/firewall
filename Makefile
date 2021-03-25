CFLAGS = -Wall -Wextra -std=gnu89 -O0 -g

OBJS = firewall.o \
       bpf_program.o
       syscalls.o

firewall: $(OBJS)

.phony: clean
clean:
	$(RM) $(OBJS)
	$(RM) firewall
