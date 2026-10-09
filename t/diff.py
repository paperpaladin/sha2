#!/usr/bin/env python3
"""t/diff.py -- differential oracle: our answers against independent ones.

SPDX-License-Identifier: GPL-3.0-or-later

Three independent references, all of which must agree with us on every input:

  1. CPython hashlib
  2. GNU coreutils sha224sum / sha256sum / sha384sum / sha512sum
  3. openssl dgst (a reference only -- the library does not link against it)

The exhaustive length sweep is the point: every length from 0 to 2048
inclusive, so every padding case -- length field spilling into a second
block, the exact block multiples, the empty input -- is covered rather than
sampled.
"""
import hashlib
import hmac
import os
import random
import subprocess
import sys

TST = sys.argv[1] if len(sys.argv) > 1 else "./t/tst"
ALGS = ["sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256"]
HL = {"sha512-224": "sha512_224", "sha512-256": "sha512_256"}
# coreutils has no tool for the truncated SHA-512 variants.
COREUTILS = {"sha224": "sha224sum", "sha256": "sha256sum",
             "sha384": "sha384sum", "sha512": "sha512sum"}
fails = 0
skipped = []


def ok(cond, what):
    global fails
    print(("ok - " if cond else "not ok - ") + what)
    if not cond:
        fails += 1


def pattern(n):
    """Must match pattern() in t/tst.c, computed independently."""
    return bytes((i * 31 + 7) & 0xFF for i in range(n))


def hl(alg, data):
    return hashlib.new(HL.get(alg, alg), data).hexdigest()


def sweep(maxlen=2048):
    data = pattern(maxlen)
    for alg in ALGS:
        out = subprocess.run([TST, "sweep", alg, str(maxlen)],
                             capture_output=True, check=True).stdout.decode()
        lines = out.split()
        bad = []
        n = 0
        for i in range(0, len(lines), 2):
            n = int(lines[i])
            if lines[i + 1] != hl(alg, data[:n]):
                bad.append(n)
        ok(len(lines) // 2 == maxlen + 1 and not bad,
           "%s: lengths 0..%d vs hashlib%s"
           % (alg, maxlen, "" if not bad else " FAILED at " + str(bad[:8])))


def have(prog):
    return subprocess.run(["sh", "-c", "command -v " + prog],
                          capture_output=True).returncode == 0


def coreutils(alg, data):
    """GNU coreutils.  Independent of hashlib: its own SHA code, not
    OpenSSL's."""
    prog = COREUTILS.get(alg)
    if prog is None or not have(prog):
        return None
    out = subprocess.run([prog], input=data, capture_output=True,
                         check=True).stdout.decode()
    return out.split()[0]


def openssl(alg, data):
    """openssl dgst.  Covers all six, including the two coreutils has no tool
    for.  openssl is a reference here and never a dependency: nothing in the
    library links against it."""
    if not have("openssl"):
        return None
    p = subprocess.run(["openssl", "dgst", "-" + alg, "-r"], input=data,
                       capture_output=True)
    if p.returncode != 0:
        return None
    return p.stdout.decode().split()[0]


def run(args, data):
    p = subprocess.run([TST] + args, input=data, capture_output=True,
                       check=True)
    return p.stdout.decode().split()[0]


def streaming():
    """Random data, random lengths up to 10MB, fed through the streaming API
    in pseudorandom chunk sizes.  Must equal hashlib, and the one-shot read
    must equal the chunked read."""
    rng = random.Random(20261009)
    sizes = [0, 1, 127, 128, 129, 4096] + \
            [rng.randrange(1, 10 << 20) for _ in range(4)]
    for n in sizes:
        data = rng.randbytes(n)
        for alg in ALGS:
            want = hl(alg, data)
            one = run(["hex", alg], data)
            many = run(["chunks", alg, str(rng.randrange(1, 1 << 62))], data)
            ok(one == want and many == want,
               "%s: %d random bytes, one-shot and chunked, vs hashlib"
               % (alg, n))


def hmac_keylens():
    """Every key length from 0 to 200, against Python's hmac.  That spans
    shorter than, equal to and longer than both block sizes (64 and 128), so
    the hash-the-long-key branch is covered on both sides of both."""
    for alg in ALGS:
        out = subprocess.run([TST, "hmacsweep", alg, "200"],
                             capture_output=True, check=True).stdout.decode()
        lines = out.split()
        bad = []
        for i in range(0, len(lines), 2):
            n = int(lines[i])
            want = hmac.new(pattern(n), b"the message",
                            lambda d=b"": hashlib.new(HL.get(alg, alg), d))
            if lines[i + 1] != want.hexdigest():
                bad.append(n)
        ok(len(lines) // 2 == 201 and not bad,
           "hmac-%s: key lengths 0..200 vs python hmac%s"
           % (alg, "" if not bad else " FAILED at " + str(bad[:8])))


def big_message():
    """A message of 536,870,913 bytes -- 4,294,967,304 bits, just over 2^32.

    This is the only test that exercises the top half of the 64-bit length
    field, so it is the only thing proving the length encoding is not
    truncated to 32 bits.  One algorithm of each width is enough: the padding
    code is shared and the widths differ only in the field size.

    SHA-512's length field is 128 bits and its top 64 bits are unreachable --
    that would need an exabyte of input -- so they stay untested, which the
    README says plainly rather than implying coverage.
    """
    n = (1 << 29) + 1
    blk = bytes((i * 31 + 7) & 0xFF for i in range(1 << 20))
    for alg in ("sha256", "sha512"):
        h = hashlib.new(HL.get(alg, alg))
        left = n
        while left:
            k = min(left, len(blk))
            h.update(blk[:k])
            left -= k
        ours = subprocess.run([TST, "big", alg, str(n)], capture_output=True,
                              check=True).stdout.decode().split()[0]
        ok(ours == h.hexdigest(),
           "%s: %d bytes (%d bits, past 2^32) vs hashlib" % (alg, n, n * 8))


def pbkdf2():
    """RFC 6070's inputs with HMAC-SHA-2, against hashlib and openssl kdf.
    RFC 6070's own digests are HMAC-SHA-1, which this library does not
    implement, so the iteration counts are the RFC's and the expected values
    are two independent implementations' rather than the RFC's."""
    for alg in ALGS:
        for iters in (1, 2, 4096):
            for dklen in (1, 20, 100):
                ours = subprocess.run(
                    [TST, "pbkdf2", alg, str(iters), str(dklen)],
                    capture_output=True, check=True).stdout.decode().split()[0]
                want = hashlib.pbkdf2_hmac(HL.get(alg, alg), b"password",
                                           b"salt", iters, dklen).hex()
                refs = [("hashlib", want)]
                o = openssl_kdf(alg, iters, dklen)
                if o is None:
                    if "openssl kdf" not in skipped:
                        skipped.append("openssl kdf")
                else:
                    refs.append(("openssl kdf", o))
                bad = [n for n, r in refs if r != ours]
                ok(not bad, "pbkdf2-%s c=%d dkLen=%d vs %s%s"
                   % (alg, iters, dklen, " and ".join(n for n, _ in refs),
                      "" if not bad else " DISAGREE: " + str(bad)))


def openssl_kdf(alg, iters, dklen):
    if not have("openssl"):
        return None
    name = {"sha512-224": "SHA512-224", "sha512-256": "SHA512-256"}.get(
        alg, alg.upper())
    p = subprocess.run(["openssl", "kdf", "-keylen", str(dklen),
                        "-kdfopt", "digest:" + name,
                        "-kdfopt", "pass:password", "-kdfopt", "salt:salt",
                        "-kdfopt", "iter:" + str(iters), "PBKDF2"],
                       capture_output=True)
    if p.returncode != 0:
        return None
    return p.stdout.decode().strip().replace(":", "").lower()


def references():
    """Every reference must agree with us, on inputs chosen to hit the cases
    that break padding: the empty input and both sides of both boundaries."""
    rng = random.Random(4231)
    cases = [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"a" * 111,
             b"a" * 112, b"a" * 119, b"a" * 120, b"a" * 128,
             rng.randbytes(100000)]
    for alg in ALGS:
        agree = disagree = 0
        missing = []
        for data in cases:
            ours = run(["hex", alg], data)
            for name, ref in (("hashlib", hl(alg, data)),
                              ("coreutils", coreutils(alg, data)),
                              ("openssl", openssl(alg, data))):
                if ref is None:
                    if name not in missing:
                        missing.append(name)
                    continue
                if ref == ours:
                    agree += 1
                else:
                    disagree += 1
        for m in missing:
            skipped.append("%s has no %s equivalent" % (alg, m))
        ok(disagree == 0 and agree > 0,
           "%s: %d comparisons against independent implementations agree%s"
           % (alg, agree, "" if not missing else " (%s)" % ", ".join(missing)))


def clone_contract():
    """final() twice and update() after final() must match hashlib, whose
    contract we copied."""
    for alg in ALGS:
        h = hashlib.new(HL.get(alg, alg))
        h.update(b"abc")
        first = h.hexdigest()
        h.update(b"def")
        second = h.hexdigest()
        got = subprocess.run([TST, "restate", alg], capture_output=True,
                             check=True).stdout.decode().split()
        ok(got == [first, first, second],
           "%s: hashlib agrees that final() does not consume the context"
           % alg)


if __name__ == "__main__":
    sweep()
    streaming()
    hmac_keylens()
    big_message()
    pbkdf2()
    references()
    clone_contract()
    for s in skipped:
        print("skip - " + s)
    print("%d failed" % fails)
    sys.exit(1 if fails else 0)
