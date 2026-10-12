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

# NIST CAVP byte-oriented test vectors.  4.7MB, not committed, fetched once.
# Only the .rsp files are read; nothing from the archive is executed.
SHAZIP=scratch/shabytetestvectors.zip
HMACZIP=scratch/hmactestvectors.zip
VEC=scratch/cavp
cavp_state='SKIPPED -- vectors not fetched'
hmac_cavp_state='SKIPPED -- vectors not fetched'
if [ ! -s "$SHAZIP" ]; then
	curl -fsS --max-time 300 -o "$SHAZIP" \
		"https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip" \
		|| rm -f "$SHAZIP"
fi
if [ ! -s "$HMACZIP" ]; then
	curl -fsS --max-time 300 -o "$HMACZIP" \
		"https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/hmactestvectors.zip" \
		|| rm -f "$HMACZIP"
fi
if [ -s "$HMACZIP" ]; then
	python3 -c 'import sys,zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$HMACZIP" "$VEC" || :
fi
if [ -s "$SHAZIP" ] && python3 -c 'import sys,zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$SHAZIP" "$VEC"; then
	HAVE_CAVP=1
else
	HAVE_CAVP=0
fi

# A crash is a failure.  Piping through tee loses the exit status, and the
# first ASAN run of this suite aborted mid-way through the unit assertions
# while the run still reported "0 failed" -- so the status is checked
# explicitly and turned into a red line of its own.
# A pipeline's exit status is tee's, so the output goes to a file first and
# the status is read from the command itself.
run() {
	label=$1
	shift
	st=0
	"$@" > scratch/last.log 2>&1 || st=$?
	tee -a "$OUT" < scratch/last.log
	[ "$st" = 0 ] ||
		say "not ok - $label exited $st (crash, abort or sanitizer)"
}

# The 192 constants in sha2.c must equal what their FIPS 180-4 definitions
# produce -- cube and square roots of the first primes, and for the two
# truncated variants, SHA-512 with a xored IV over the string "SHA-512/t".
# tools/genk.py derives them and diffs them against the committed source.
printf -- '--- oracle: constants in sha2.c match their definitions\n'
run "tools/genk.py" python3 tools/genk.py check sha2.c

printf -- '\n--- unit assertions (FIPS 180-4 examples, padding boundaries)\n'
run "t/tst unit" ./t/tst unit

# Oracle 1: NIST CAVP.  The pass rate is printed per algorithm per file, which
# is the number this repo is judged on.
if [ "$HAVE_CAVP" = 1 ]; then
	printf -- '\n--- oracle 1: NIST CAVP byte test vectors\n'
	for a in sha224 sha256 sha384 sha512 sha512-224 sha512-256; do
		case $a in
		sha512-224) stem=SHA512_224 ;;
		sha512-256) stem=SHA512_256 ;;
		*) stem=$(printf '%s' "$a" | tr 'a-z' 'A-Z') ;;
		esac
		for kind in ShortMsg LongMsg Monte; do
			f="$VEC/shabytetestvectors/$stem$kind.rsp"
			[ -s "$f" ] || { say "not ok - CAVP $stem$kind.rsp missing from the archive"; continue; }
			case $kind in
			Monte) run "tst monte $a" ./t/tst monte "$a" "$f" ;;
			*) run "tst cavp $a" ./t/tst cavp "$a" "$f" ;;
			esac
		done
	done
	cavp_state='ran'
fi
if [ -s "$VEC/HMAC.rsp" ]; then
	run "tst hmaccavp" ./t/tst hmaccavp "$VEC/HMAC.rsp"
	hmac_cavp_state='ran'
fi

# Oracle: CPython hashlib, over every length from 0 to 2048 so that no
# padding or block-boundary case is merely sampled.
printf -- '\n--- oracle: differential against CPython hashlib\n'
run "t/diff.py" python3 t/diff.py ./t/tst

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

# A suite that cannot fail is not a suite.  Each sabotage is one character of
# sha2.c, applied to a copy, compiled, and run: the suite must go red.  If a
# sabotage passes, the harness is not testing what it claims and that is a
# failure of this run, not a curiosity.
printf -- '\n--- sabotage: the suite must go red for a broken implementation\n'
sab() {
	name=$1
	expr=$2
	sed "$expr" sha2.c > scratch/sab.c
	if cmp -s scratch/sab.c sha2.c; then
		say "not ok - sabotage [$name]: the edit did not apply"
		return
	fi
	# shellcheck disable=SC2086
	if ! $CC $CFLAGS -I. -o scratch/sabtst t/tst.c scratch/sab.c \
		2>/dev/null; then
		say "not ok - sabotage [$name]: does not compile"
		return
	fi
	: > scratch/sab.log
	# The constant check reads the source, so it sees a sabotaged table
	# even though the vectors are what catch a sabotaged algorithm.
	python3 tools/genk.py check scratch/sab.c >> scratch/sab.log 2>&1 || :
	./scratch/sabtst unit >> scratch/sab.log 2>&1 || :
	if [ "$HAVE_CAVP" = 1 ]; then
		./scratch/sabtst cavp sha256 \
			"$VEC/shabytetestvectors/SHA256ShortMsg.rsp" \
			>> scratch/sab.log 2>&1 || :
		./scratch/sabtst monte sha512 \
			"$VEC/shabytetestvectors/SHA512Monte.rsp" \
			>> scratch/sab.log 2>&1 || :
	fi
	red=$(grep -c '^not ok' scratch/sab.log || :)
	if [ "$red" -gt 0 ]; then
		say "ok - sabotage [$name]: $red checks go red"
	else
		say "not ok - sabotage [$name]: suite still passes, so it is"
		say "         not testing what it claims to test"
	fi
}
sab "round constant K256[0] 0x428a2f98 -> 0x428a2f99" \
	's/0x428a2f98u/0x428a2f99u/'
sab "padding byte 0x80 -> 0x81" \
	's/c\.buf\[c\.buflen++\] = 0x80;/c.buf[c.buflen++] = 0x81;/'
sab "length encoding: bit count nlo<<3 -> nlo<<2" \
	's/uint64_t bitlo = c\.nlo << 3;/uint64_t bitlo = c.nlo << 2;/'

# The roster reports what happened. Lines 2 through 6 used to be literal
# printf statements that said "ran" whichever way the run went: openssl is
# only ever invoked from t/diff.py behind a have("openssl") guard, so on a
# machine without it the roster claimed an oracle that had been skipped, and
# coreutils has no tool for sha512-224 or sha512-256 so its "ran" was
# overstated even here. A roster that cannot say "SKIPPED" is decoration.
tool_state() {
	if command -v "$1" >/dev/null 2>&1; then
		printf 'ran'
	else
		printf 'SKIPPED (%s not installed)' "$1"
	fi
}
co_state=$(tool_state sha256sum)
ssl_state=$(tool_state openssl)
case $co_state in
ran) co_state='ran (4 of 6: no tool for sha512-224/256)' ;;
esac
nskip=$(grep '^skip - ' "$OUT" | wc -l)

printf -- '\n=== oracles\n'
printf -- '  1 CAVP SHA byte vectors        %s\n' "$cavp_state"
printf -- '  1 CAVP HMAC vectors            %s\n' "$hmac_cavp_state"
printf -- '  2 constants vs FIPS 180-4      ran (192 constants, no network needed)\n'
printf -- '  3 CPython hashlib / hmac       ran (no network needed)\n'
printf -- '  4 GNU coreutils sha*sum        %s\n' "$co_state"
printf -- '  5 openssl dgst and kdf         %s\n' "$ssl_state"
printf -- '  6 three sabotages, each red    ran (no network needed)\n'
printf -- '  %s check(s) skipped; see the "skip - " lines above\n' "$nskip"

pass=$(grep -c '^ok - ' "$OUT")
fail=$(grep -c '^not ok - ' "$OUT")
printf '\n%s passed, %s failed\n' "$pass" "$fail"

# Each CAVP download is checked on its own. This was
# `case $cavp_state$hmac_cavp_state in SKIPPED*)`, which tests the
# concatenation of the two: "ranSKIPPED" does not match SKIPPED*, so a
# missing HMAC vector set produced no warning and SHA2_REQUIRE_CAVP=1 did not
# fail on it. Only a skip of the *first* one was ever noticed.
cavp_missing=''
case $cavp_state in SKIPPED*) cavp_missing='SHA byte vectors' ;; esac
case $hmac_cavp_state in
SKIPPED*)
	if [ -n "$cavp_missing" ]; then
		cavp_missing="$cavp_missing and HMAC vectors"
	else
		cavp_missing='HMAC vectors'
	fi
	;;
esac
if [ -n "$cavp_missing" ]; then
	printf 'WARNING: the CAVP %s did not download, so this run proves\n' \
		"$cavp_missing"
	printf 'much less than a full one.  SHA2_REQUIRE_CAVP=1 makes that a\n'
	printf 'failure instead of a warning.\n'
	[ "${SHA2_REQUIRE_CAVP:-0}" = 1 ] && exit 1
fi
[ "$fail" -eq 0 ]
