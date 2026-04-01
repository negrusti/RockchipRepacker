CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

all: rkimg

rkimg: src/rkimg.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f rkimg

.PHONY: all clean
