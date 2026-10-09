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

# shellcheck disable=SC2086
$CC $CFLAGS -o t/tst t/tst.c sha2.c || { echo "not ok - compile t/tst"; exit 1; }

printf -- '--- unit assertions (FIPS 180-4 examples, padding boundaries)\n'
./t/tst unit 2>&1 | tee -a "$OUT"

pass=$(grep -c '^ok - ' "$OUT")
fail=$(grep -c '^not ok - ' "$OUT")
printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
