# sha2

SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256 in one C11
file, with HMAC (RFC 2104) and PBKDF2 (RFC 8018) on top, a streaming
init/update/final API, and a CLI that hashes stdin or named files.

No dependencies beyond libc.  gcc, `make`, done.

## This is NOT security-critical code

Read this before using it for anything.

- It is not constant-time.  Nothing here is written to take the same
  number of cycles regardless of its input or key.
- It is not side-channel hardened.  No attention has been paid to cache
  behaviour, branch prediction, or power analysis.
- It does not wipe or lock memory.  Keys, passwords and intermediate HMAC
  state are left on the stack for the next function to overwrite whenever it
  gets round to it.  PBKDF2 does not `mlock`.
- It does not compare tags.  `sha2_hmac_final()` hands you bytes; whether
  your comparison needs to be constant-time is your decision, and this file
  will not make a tempting wrong one available.

Do not use it where any of that matters.  Use libsodium or your platform's
crypto library.  What this code is good for is being *correct*: it agrees with
the NIST vectors and with three independent implementations, byte for byte, and
that is the only claim being made.

## Score against the official vectors

NIST CAVP byte-oriented test vectors, fetched by `t/run.sh` from
csrc.nist.gov.  Pass rate per algorithm per file, the number this
repo exists to report:

```
                 ShortMsg   LongMsg   Monte Carlo
SHA-224            65/65      64/64   100/100 checkpoints
SHA-256            65/65      64/64   100/100
SHA-384          129/129    128/128   100/100
SHA-512          129/129    128/128   100/100
SHA-512/224      129/129    128/128   100/100
SHA-512/256      129/129    128/128   100/100
                 -------    -------   -----------
                 646/646    640/640   600/600

HMAC.rsp   hmac-sha224  375/375
           hmac-sha256  225/225
           hmac-sha384  300/300
           hmac-sha512  375/375
                        -------
                        1275/1275
           plus 300 HMAC-SHA-1 vectors SKIPPED -- no SHA-1 in this library
```

**1286 message vectors, 1275 HMAC vectors, 600 Monte Carlo checkpoints, and
nothing fails.**  Each Monte Carlo checkpoint is the end of 1000 hashes whose
input is the concatenation of the previous three digests, so the 600
checkpoints stand for 600,000 chained hashes. That is the mode that catches an
`init()` which leaves the buffer dirty or a `final()` which corrupts the state
it just read, because nothing downstream of such a bug ever runs in a
single-hash test.

The CAVP files are not committed (4.7MB of zip).  `t/run.sh` fetches them once
into `scratch/`, reads only the `.rsp` text, and executes nothing from the
archives.  Without the network the run prints `SKIPPED` in its oracle roster
and says the score proves less; `SHA2_REQUIRE_CAVP=1` turns the skip into a
failure.

## Three independent references, all agreeing

A fourth claim, separate from the CAVP score: three implementations nobody here
wrote agree with this one on every input the differential tests generate.

| reference | what it covers | independent of |
| --- | --- | --- |
| CPython `hashlib` / `hmac` | all six hashes, HMAC, PBKDF2 | coreutils |
| GNU coreutils `sha224sum`, `sha256sum`, `sha384sum`, `sha512sum` | four hashes; its own SHA code, not OpenSSL's | hashlib, openssl |
| `openssl dgst`, `openssl kdf` | all six hashes, PBKDF2 | coreutils |

`openssl` is a reference, never a dependency.  It is invoked as a
subprocess by `t/diff.py`; nothing in `sha2.c` or the test program links
against libcrypto.

coreutils ships no tool for SHA-512/224 or SHA-512/256, so those two report a
`skip` line naming the missing reference instead of quietly counting fewer
comparisons.  A skipped oracle must not look like a passing one.

What the differential tests feed them:

- Every length from 0 to 2048 bytes, for all six algorithms.  Exhaustive,
  not sampled: 12,294 digests.  This is the test that covers padding, because
  every block boundary and every length where the length field stops fitting
  is in the range by construction.
- Random data at random lengths up to 10MB, each hashed both one-shot and
  through the streaming API in pseudorandom chunk sizes from 0 to 4096 bytes,
  which must give the same answer.
- Every HMAC key length from 0 to 200 bytes, which spans shorter than, equal
  to and longer than both block sizes (64 and 128), so the branch that hashes
  an over-long key first is exercised on both sides of both boundaries.
- One message of 536,870,913 bytes: 4,294,967,304 bits, just past 2^32,
  for one algorithm of each width.  Nothing else in the suite reaches that, so
  without it the length field could be truncated to 32 bits and every other
  test would still pass.  It costs 3.6 seconds, because the generated pattern
  is periodic with period 256 and both sides feed a 1MB block repeatedly.
- The CLI's entire output diffed byte for byte against `sha256sum` and friends
  over three files at once, so the output format and the multi-file loop are
  checked by an outside program and not by a string in a test.

## Published vectors in standards documents

- FIPS 180-4 appendices B and C: the worked examples for SHA-256 and SHA-512.
- RFC 4231 cases 1 to 7, all four algorithms the RFC covers: 28 HMAC vectors.
  Cases 6 and 7 use a 131-byte key, longer than both block sizes, the
  hash-the-key-first step implementations skip.
- RFC 7914 section 11: two PBKDF2-HMAC-SHA-256 vectors, c=1 dkLen=64 and
  c=80000 dkLen=64.
- The 192 round constants and initial hash values are **not typed in**, and
  are re-derived and diffed on every test run.  `tools/genk.py` computes
  them from their FIPS 180-4 definitions, cube and square roots of the first
  primes, and derives the two SHA-512/t IVs the way section 5.3.6 defines
  them, by running SHA-512 with its IV xored by `0xa5a5...` over the string
  `"SHA-512/224"` or `"SHA-512/256"`.  It checks its own Python SHA-512
  against hashlib before using it to derive anything, then reads the hex
  literals back out of `sha2.c` and compares.

  This oracle caught a real derivation error on its first run: SHA-224's IV is
  the second 32 bits of the fractional part of the square roots of the
  9th to 16th primes, not the first.  Eight of the forty-eight IV constants
  disagreed, and the script was wrong, not `sha2.c`, but the same
  mistake made while typing the table in would have produced a library that
  failed every SHA-224 vector.

## Watching the harness fail

A suite that has never been seen failing is not evidence.  Three
one-character defects are injected into a copy of `sha2.c` on every
`make test` run, compiled, and run against the unit assertions plus CAVP
SHA256ShortMsg and CAVP SHA512Monte.  If a sabotaged copy still passes, the
run fails.

| sabotage | result |
| --- | --- |
| round constant `K256[0]` `0x428a2f98` -> `0x428a2f99` | **31 checks red.**  `tools/genk.py` reports 1 of 64 constants differing from its definition.  CAVP SHA256ShortMsg 0/65.  SHA512Monte stays green, correctly: that constant is only in the 32-bit core. |
| padding byte `0x80` -> `0x81` | **56 checks red.**  SHA256ShortMsg 0/65, SHA512Monte 0/100. |
| bit length `nlo << 3` -> `nlo << 2` | **54 checks red.**  SHA256ShortMsg scores **1/65**. |

That last row is the one worth reading.  The single surviving vector is the
empty message, where `0 << 3` and `0 << 2` are both zero, so the
empty-input test everybody writes cannot see a broken length encoding, and the
exhaustive sweep and the CAVP files are what actually catch it.

The sabotage runner also fails if the `sed` edit did not change the file or the
sabotaged copy does not compile, because an expression that silently stops
matching after a refactor would otherwise report a pass for a sabotage that
was never applied.

### The bug this found in the harness itself

The first `make test-asan` run aborted inside the unit assertions and the
suite printed "172 passed, 0 failed" and exited 0 with 68 assertions never
run.  Two defects:

1. The test program wrote 10 bytes past the end of a stack buffer: a label
   appended after 128 hex characters in a 129-byte array.  In the test code,
   not in `sha2.c`.  gcc had been warning about it and the warning was
   scrolling past in the test compile.
2. `t/run.sh` piped the test program through `| tee -a`, and a pipeline's exit
   status is `tee`'s.  The abort was invisible.

Every test invocation now goes through a `run()` wrapper that reads the status
from the command itself and emits its own red line on any non-zero exit,
verified by pointing it at a process that segfaults after printing an `ok`
line.  Of the two, the second was much worse: the first was a bug, the second
was a suite that could not report one.

## Build and test

```sh
make                # sha2.o and the sha2 CLI; gcc and nothing else
make test           # every oracle; about 10 seconds
make test-asan      # the same, under -fsanitize=address,undefined (~40s)
make bench          # throughput per algorithm, PBKDF2 iterations/s
make clean
```

`make test` needs the network the first time, to fetch the CAVP archives.
It prints 243 `ok` lines, an oracle roster saying which of the six oracles
actually ran, and `N passed, M failed`.

## API

```c
enum sha2_alg { SHA2_224, SHA2_256, SHA2_384, SHA2_512,
                SHA2_512_224, SHA2_512_256 };

void   sha2_init(struct sha2_ctx *c, enum sha2_alg alg);
void   sha2_update(struct sha2_ctx *c, const void *data, size_t len);
void   sha2_final(const struct sha2_ctx *c, unsigned char *out);
void   sha2(enum sha2_alg alg, const void *data, size_t len,
            unsigned char *out);

size_t sha2_digest_size(enum sha2_alg alg);
size_t sha2_block_size(enum sha2_alg alg);
const char *sha2_name(enum sha2_alg alg);
int    sha2_by_name(const char *name, enum sha2_alg *out);

void   sha2_hmac_init(struct sha2_hmac_ctx *c, enum sha2_alg alg,
                      const void *key, size_t keylen);
void   sha2_hmac_update(struct sha2_hmac_ctx *c, const void *data, size_t len);
void   sha2_hmac_final(const struct sha2_hmac_ctx *c, unsigned char *out);
void   sha2_hmac(enum sha2_alg alg, const void *key, size_t keylen,
                 const void *msg, size_t msglen, unsigned char *out);

int    sha2_pbkdf2(enum sha2_alg alg, const void *pw, size_t pwlen,
                   const void *salt, size_t saltlen, uint32_t iters,
                   unsigned char *out, size_t outlen);
```

`sha2_final()` takes a const context on purpose.  It pads a copy, so:

- calling `final()` twice returns the same digest, and
- `update()` after `final()` continues the same message.

That is CPython hashlib's contract, chosen deliberately so the behaviour has
an outside oracle: `t/diff.py` checks all three calls against hashlib doing
the same three calls, for all six algorithms.  There is no "context consumed"
error state to get wrong, and no way to accidentally hash a padded state.

A `struct sha2_ctx` and a `struct sha2_hmac_ctx` are plain copyable values;
assignment is a supported clone.  That is how PBKDF2's inner loop avoids
redoing the key schedule 80,000 times.

`sha2_pbkdf2()` returns 0, or -1 for `iters == 0` or a derived key longer than
`(2^32 - 1)` blocks.  Nothing in the file allocates.

## CLI

```
sha2 [-a ALG] [FILE...]
ALG: sha224 sha256 sha384 sha512 sha512-224 sha512-256   (default sha256)
```

Reads stdin when given no files, or for `-`.  The output format is coreutils'
exactly (lowercase hex, two spaces, the name) so `sha2 -a sha256 f` is
byte-identical to `sha256sum f` and its output feeds `sha256sum -c`.  `-a`
also accepts `sha-256`, `256`, `SHA512/256` and similar.

## What does NOT work

- No SHA-1, by choice.  It costs two things: RFC 6070's published PBKDF2
  vectors are all HMAC-SHA-1 and cannot be checked here at all, and 300 of the
  CAVP HMAC vectors are skipped.  Instead, RFC 6070's *inputs* (password
  "password", salt "salt", 1, 2 and 4096 iterations) are run with HMAC-SHA-2
  against hashlib and `openssl kdf`: the iteration counts are the RFC's, the
  expected values are two independent implementations'.  **This README does not
  claim an RFC 6070 pass rate**, because there is no honest one to claim.
- The upper 64 bits of SHA-512's length field are untested, and
  untestable: reaching them needs 2^64 bytes of input.  The low 64 bits are
  exercised past 2^32 bits by a 512MB message.  The code treats the counter as
  128-bit throughout, but only the bottom half has ever been fed a value.
- Never run on a big-endian machine.  Every word is loaded and stored one
  byte at a time, so the code should be endian-neutral, but that is an
  argument, not a test, and no big-endian hardware or cross toolchain is
  available here.  Do not assume it works there.
- Not constant-time, not hardened, no memory wiping.  See the top of this
  file.  There is no `sha2_hmac_verify()` precisely because a correct one
  needs a constant-time comparison and this file does not provide one.
- SHA-512/t only for t = 224 and 256.  The general construction from FIPS
  180-4 section 5.3.6 is not implemented. The two standard variants have
  their IVs in a table.
- The CLI has no `-c` check mode, no `--hmac`, no PBKDF2, no `--tag`, no
  `-b`/`-t` modes.  It hashes things and prints them.
- The CLI does not escape filenames.  coreutils prefixes a line with `\`
  and escapes newlines and backslashes in the name. This does not, so for a
  file whose name contains a newline the output is not parseable and not
  identical to coreutils'.  Every other name matches byte for byte.
- No SIMD.  226 MB/s for the 32-bit core and 344 MB/s for the 64-bit one
  on this machine.  SHA-NI is roughly 4x for SHA-256.  Marked `shortcut:` in
  `sha2.c` with the upgrade path.
- `make bench` is a rough number.  No warmup, no repeat-until-stable;
  it will notice a 2x regression and should not be trusted for less.
- No HKDF, no scrypt, no Argon2, no SHA-3.  HKDF is next in `PLAN.md`
  because RFC 5869 publishes vectors for it.
- `sha2_update()` takes a `size_t`, so on a 32-bit platform a single call is
  limited to 4GB even though the internal counter is not.  Call it twice.

## Layout

```
sha2.c      the library, and the CLI behind -DSHA2_CLI
sha2.h      the API, and the warning
t/tst.c     every C-side test, by subcommand: unit, sweep, chunks, cavp,
            monte, hmaccavp, pbkdf2, big, bench
t/diff.py   the three local references and the generated differentials
t/run.sh    fetches the vectors, runs everything, runs the sabotages,
            prints the oracle roster and "N passed, M failed"
tools/genk.py  derives the 192 constants from their definitions and diffs
               them against sha2.c; `emit` prints the C
```

Six files of code, two of them the library.  `scratch/` holds the downloaded
vectors and every test temporary. It is repo-local on purpose, because `/tmp`
is shared with other work here and has collided before.

## Licence

GPL-3.0-or-later.  See `LICENSE`.
