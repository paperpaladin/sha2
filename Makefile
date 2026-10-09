# sha2 -- SPDX-License-Identifier: GPL-3.0-or-later
#
# t/run.sh compiles the test programs, so test-asan is a CFLAGS override and
# nothing more.  -ffile-prefix-map keeps the build reproducible: without it -g
# writes $(CURDIR) into DWARF .debug_line_str.

CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g -ffile-prefix-map=$(CURDIR)=.
ASAN     = -std=c11 -Wall -Wextra -Wpedantic -O1 -g \
	   -fsanitize=address,undefined -fno-omit-frame-pointer \
	   -ffile-prefix-map=$(CURDIR)=.

.PHONY: all test clean

# No sources yet, and every commit in this repo has to build: the targets
# that need sha2.c arrive with sha2.c in the next commit.
all:
	@echo 'nothing to build yet'

test: all
	@echo 'no tests yet'

clean:
	rm -f sha2.o sha2 t/tst
	rm -rf scratch
