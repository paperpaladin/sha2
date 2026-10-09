#!/bin/sh
# t/run.sh -- build and run every oracle, print "N passed, M failed".
# SPDX-License-Identifier: GPL-3.0-or-later
#
# POSIX sh.  This script, not the Makefile, compiles the test program, so
# `make test-asan` is the same script with different CFLAGS.
set -u

cd "$(dirname "$0")/.." || exit 1
CC=${CC:-gcc}
CFLAGS=${CFLAGS:--std=c11 -Wall -Wextra -Wpedantic -O2 -g}

mkdir -p scratch		# repo-local: /tmp is shared with other work
OUT=scratch/run.log
: > "$OUT"

say() { printf '%s\n' "$*" | tee -a "$OUT"; }

# shellcheck disable=SC2086
$CC $CFLAGS -o t/tst t/tst.c sha2.c || { echo "not ok - compile t/tst"; exit 1; }

printf -- '--- unit assertions (FIPS 180-4 examples, padding boundaries)\n'
./t/tst unit 2>&1 | tee -a "$OUT"

# Oracle: CPython hashlib, over every length from 0 to 2048 so that no
# padding or block-boundary case is merely sampled.
printf -- '\n--- oracle: differential against CPython hashlib\n'
python3 t/diff.py ./t/tst 2>&1 | tee -a "$OUT"

# The CLI prints coreutils' format, so coreutils itself is the oracle for it:
# byte-for-byte identical output on the same files, for the four algorithms it
# has a tool for.
printf -- '\n--- oracle: CLI output byte-identical to coreutils\n'
$CC $CFLAGS -DSHA2_CLI -o scratch/sha2cli sha2.c || exit 1
head -c 100000 /dev/urandom > scratch/a.bin
: > scratch/empty.bin
printf 'x' > scratch/one.bin
for a in 224 256 384 512; do
	if ./scratch/sha2cli -a "sha$a" scratch/a.bin scratch/empty.bin \
		scratch/one.bin > scratch/ours.txt &&
		"sha${a}sum" scratch/a.bin scratch/empty.bin scratch/one.bin \
			> scratch/theirs.txt &&
		cmp -s scratch/ours.txt scratch/theirs.txt; then
		say "ok - CLI output matches sha${a}sum byte for byte"
	else
		say "not ok - CLI output matches sha${a}sum byte for byte"
	fi
done
# stdin, and the name coreutils uses for it
if [ "$(./scratch/sha2cli < scratch/a.bin)" = \
	"$(sha256sum < scratch/a.bin | sed 's,  -,  -,')" ]; then
	say "ok - CLI on stdin matches sha256sum on stdin"
else
	say "not ok - CLI on stdin matches sha256sum on stdin"
fi
if ./scratch/sha2cli -a nosuch < /dev/null 2>/dev/null; then
	say "not ok - CLI rejects an unknown algorithm"
else
	say "ok - CLI rejects an unknown algorithm"
fi
if ./scratch/sha2cli scratch/nonexistent 2>/dev/null; then
	say "not ok - CLI fails on an unopenable file"
else
	say "ok - CLI fails on an unopenable file"
fi

pass=$(grep -c '^ok - ' "$OUT")
fail=$(grep -c '^not ok - ' "$OUT")
printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
