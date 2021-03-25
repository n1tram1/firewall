CC = gcc
CPPFLAGS = -D_DEFAULT_SOURCE
CFLAGS = -Wall -Wextra -std=c99 -O0 -g

OBJS = firewall.o \
       bpf_program.o \
       syscalls.o


firewall: $(OBJS)

.phony: clean
clean:
	$(RM) $(OBJS)
	$(RM) firewall
