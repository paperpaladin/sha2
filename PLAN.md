# PLAN

## Contract

`sha2` is a single C11 file holding the whole SHA-2 family, HMAC over it, and
PBKDF2 over that.

- Six hashes: `SHA2_224`, `SHA2_256`, `SHA2_384`, `SHA2_512`, `SHA2_512_224`,
  `SHA2_512_256`.  FIPS 180-4.
- Streaming: `sha2_init` / `sha2_update` / `sha2_final`, plus a one-shot
  `sha2()`.  `sha2_final()` takes a const context. It pads a copy, so
  calling it twice returns the same digest and `update()` after `final()`
  continues the same message.  That is CPython hashlib's contract, chosen so
  the behaviour has an outside oracle instead of being an opinion.
- `sha2_hmac_*` (RFC 2104), streaming for the same reason PBKDF2 needs it.
- `sha2_pbkdf2` (RFC 8018 section 5.2).  No allocation anywhere in the file.
- A CLI, `sha2 [-a ALG] [FILE...]`, printing coreutils' exact output format so
  that coreutils can be its oracle.
- Not in the contract: constant-time anything, side-channel resistance,
  memory wiping, tag comparison, SHA-1, SHA-3, SHA-512/t for t other than 224
  and 256, keyed hashing other than HMAC.

## Hard invariant

Every vector in the NIST CAVP byte-oriented test sets passes, and all three
local reference implementations agree with us on every input the differential
tests generate.  Specifically: 1286 ShortMsg/LongMsg vectors, 600 Monte Carlo
checkpoints standing for 600,000 chained hashes, 1275 HMAC vectors, and zero
disagreements with CPython hashlib, GNU coreutils and openssl across the
exhaustive length sweep.

"Most vectors pass" is not a weaker version of this. It means a wrong answer
exists, and a hash function with a wrong answer has no use at all.

The consequence that shapes the test code. That exhaustive sweep over every length from 0 to 2048 is not a nicety.  Padding bugs live at specific lengths
(55/56 and 111/112, where the length field stops fitting), and a sampled sweep
can miss them while a sabotage experiment proves the suite would not have
noticed.

## Oracle

Ranked by how little we control them, strongest first.

1. NIST CAVP byte test vectors: `shabytetestvectors.zip` and
   `hmactestvectors.zip` from csrc.nist.gov.  Official, byte-exact, and
   including the Monte Carlo mode that chains 100,000 hashes per algorithm and
   so catches state-handling defects a single hash cannot see.  `t/run.sh`
   fetches them. A failed fetch prints SKIPPED in the oracle roster and
   `SHA2_REQUIRE_CAVP=1` turns that into a failure.
2. The constants against their own definitions.  `tools/genk.py` derives
   all 192 round constants and initial hash values from the cube and square
   roots of the first primes, derives the two SHA-512/t IVs by the section
   5.3.6 construction using a Python SHA-512 it first checks against hashlib,
   and then diffs the lot against the hex literals in `sha2.c`.  This is an
   oracle for the tables that is independent of any test vector, and it
   caught a wrong SHA-224 derivation on its first run (the IV is the second
   32 bits of the fraction, not the first).
3. Published vectors in standards documents.  FIPS 180-4 appendices B and
   C, RFC 4231 cases 1 to 7 for HMAC over all four algorithms it covers, and
   RFC 7914 section 11's two PBKDF2-HMAC-SHA-256 vectors.  RFC 6070's vectors
   are PBKDF2-HMAC-SHA-1 and cannot be used here. Only its inputs are, and the
   README says so.
4. Three independent local implementations, all of which must agree on
   every input: CPython `hashlib` and `hmac`, GNU coreutils `sha224sum` and
   friends (its own SHA code, not OpenSSL's), and `openssl dgst` / `openssl
   kdf`.  openssl is a reference here and never a dependency: nothing links
   against libcrypto.  coreutils has no tool for the two truncated SHA-512
   variants, which is reported as a skip instead of quietly counted as fewer
   comparisons.
5. Differential over generated input: every length from 0 to 2048,
   random lengths up to 10MB, the streaming API fed in pseudorandom chunks,
   HMAC key lengths 0 to 200, and one message of 536,870,913 bytes to carry the
   bit length past 2^32.
6. The suite against a sabotaged library.  Three one-character defects are
   applied to a copy of `sha2.c` on every run and the suite must go red for
   each.  If a sabotage passes, the run fails.

## Non-goals

- SHA-1 and SHA-3.  SHA-1 would be the one addition that unlocks RFC 6070 and
  300 more CAVP HMAC vectors, and it is still not worth shipping a broken hash
  to check a test vector with.
- Constant-time execution and side-channel hardening.  Stated as a
  limitation, not attempted, because attempting it halfway is worse than not.
- SIMD (SHA-NI, AVX2 multi-buffer).  Marked `shortcut:` in `sha2.c` with the
  measured ceiling.
- A `-c` check mode in the CLI, HMAC or PBKDF2 in the CLI, and filename
  escaping for names containing newlines.  All three are in the README's list
  of what does not work.

## Commit sequence

- [x] scaffolding: GPL-3, Makefile with `-ffile-prefix-map`, `.gitignore`
      why: the reproducibility flag has to be in CFLAGS before the first
      object file exists, not retrofitted.
- [x] SHA-256 compression, padding, streaming API
      why: everything else is this plus a table.  The constants are generated
      from their definitions, not typed in, so the IV derivation for
      the truncated variants is already proved before they exist.
- [x] `t/diff.py`: exhaustive 0..2048 sweep against hashlib
      why: padding is what breaks, and three published examples do not cover
      it.  SHA-224 fell out of the same commit with no new code.
- [x] padding boundaries and the context-reuse contract, named
      why: a regression should say which boundary moved.
- [x] streaming fed in pseudorandom chunk sizes, up to 10MB
      why: the one-shot and chunked paths must be the same answer, and a
      zero-length update must change nothing.
- [x] SHA-512 family: 64-bit words, 128-byte blocks, 128-bit length
      why: 384 and the two truncated variants are table entries, not code.
- [x] GNU coreutils as a second reference
- [x] `openssl dgst` as a third, and never a dependency
- [x] HMAC (RFC 2104) with RFC 4231 and a 0..200 key-length sweep
      why: the hash-the-long-key branch is the one implementations skip.
- [x] PBKDF2 (RFC 8018) with RFC 7914's vectors and RFC 6070's inputs
      why: RFC 6070's own digests are HMAC-SHA-1, which has to be said out
      loud, not substituted around.
- [x] CLI, with coreutils' output format so coreutils can diff it
- [x] CAVP ShortMsg and LongMsg, all six algorithms
- [x] CAVP Monte Carlo, 600,000 chained hashes
- [x] CAVP HMAC.rsp, 1275 vectors, SHA-1 sections reported as skipped
- [x] the 64-bit length counter past 2^32 bits
- [x] sabotage: three defects, each confirmed to turn the suite red, on every
      run, not once
- [x] `make bench`, reproducible build, and the harness bug the first ASAN run
      exposed
      why: `| tee` swallowed an ASAN abort and the suite reported 172 passed,
      0 failed with 68 assertions never run.
- [x] README and PLAN

### Next, in order

- [ ] BLOCKED: big-endian verification
      why: the code is endian-neutral by construction, every word is loaded
      and stored a byte at a time, but that is an argument, not a test, and
      no big-endian machine is available here.  `qemu-user` with a cross
      toolchain would settle it, and until it does the README says
      untested, not portable.
      blocked: nothing on this machine can execute big-endian code.  The
      host is x86_64; `qemu-user` is not installed and neither is any
      big-endian `qemu-*` target (the only qemu binaries here are
      qemu-system-x86_64, qemu-system-i386 and the disk-image tools, and a
      system emulator for x86 cannot host an s390x guest).  There is no
      cross toolchain, no `binfmt_misc` registration and no container
      runtime.  clang will emit code for s390x, ppc64, mips, mips64 and
      sparcv9, but there is no sysroot to link against and nothing to run
      the result with, so it would be a compile, not a verification.
      needs: `qemu-user` (Debian trixie candidate 1:10.0.13+ds-0+deb13u1)
      and one of gcc-s390x-linux-gnu or gcc-powerpc64-linux-gnu (both
      4:14.2.0-1), then `t/run.sh` teaching to build the suite a second
      time with the cross compiler and run it under `qemu-s390x -L
      /usr/s390x-linux-gnu`.  Real big-endian hardware would be better
      still.  All three are candidates in the configured apt repository;
      none is installed, and installing them is not this repo's decision.
      done instead: every byte-order assumption in sha2.c now lives in
      `sha2_ld32`, `sha2_st32`, `sha2_ld64` and `sha2_st64` and nowhere
      else -- the digest output loop and PBKDF2's block counter used to
      open-code the shifts a second and third time.  `tst unit` pins those
      four against byte sequences published in FIPS 180-4, and refuses a
      palindromic test vector, since 0x00000000 passes whether or not the
      helper swaps.  `t/run.sh` greps sha2.c for the host-byte-order shapes
      (a word-pointer cast, a memcpy into a word, a byte swap, a union),
      because those are correct here and wrong there, so no vector can see
      them.  A byte-swapped `sha2_st32` is the fourth standing sabotage.
      None of that is a big-endian run, and the README says so in those
      words.
- [ ] HKDF (RFC 5869) over the same HMAC
      why: it is about forty lines on top of what exists, and RFC 5869 has
      seven published vectors, so it arrives with its own oracle,
      not needing one invented.  Nothing else in this list has that property.
- [ ] `sha2_hmac_verify()` with a constant-time comparison, and only that one
      function documented as constant-time
      why: the current advice to callers is "decide for yourself", which is
      the correct default but leaves the one genuinely easy case undone.  It
      must be scoped tightly: a constant-time memcmp is testable, a
      constant-time SHA-2 core is not, and claiming both would be a lie.
- [ ] CLI `-c` check mode and coreutils' filename escaping
      why: the output format already matches coreutils byte for byte except
      for names containing newlines, so the divergence is one special case
      wide and the oracle for closing it already exists.
- [ ] SIMD core behind runtime dispatch
      why: last, because it is the only item that cannot change an answer.
      It is measured against the same vectors either way, and 226 MB/s has
      not been a problem for anything.
