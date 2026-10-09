#!/usr/bin/env python3
"""t/diff.py -- differential oracle: our answers against independent ones.

SPDX-License-Identifier: GPL-3.0-or-later

Reference 1 is CPython hashlib (OpenSSL or its own C code, either way not
ours).  The exhaustive length sweep is the point: every length from 0 to 2048
inclusive, so every padding case -- length field spilling into a second
block, the exact block multiples, the empty input -- is covered rather than
sampled.
"""
import hashlib
import os
import random
import subprocess
import sys

TST = sys.argv[1] if len(sys.argv) > 1 else "./t/tst"
ALGS = ["sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256"]
HL = {"sha512-224": "sha512_224", "sha512-256": "sha512_256"}
fails = 0


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
    clone_contract()
    print("%d failed" % fails)
    sys.exit(1 if fails else 0)
