#!/usr/bin/env python3
"""tools/genk.py -- derive SHA-2's constants and check sha2.c against them.

SPDX-License-Identifier: GPL-3.0-or-later

The round constants and the six initial hash values in sha2.c were produced
here, not typed in from a web page, and this script is the oracle for them:

    python3 tools/genk.py check sha2.c

reads the hex literals back out of sha2.c and compares them to values derived
from their FIPS 180-4 definitions --

  K256[i]  frac(cbrt(prime i)) * 2^32,  64 of them
  K512[i]  frac(cbrt(prime i)) * 2^64,  80 of them
  SHA-256  frac(sqrt(prime i)) * 2^32,  primes 1..8
  SHA-224  the SECOND 32 bits of frac(sqrt(prime i)), primes 9..16 --
           not the first, which is the subtlety in section 5.3.2 and the one
           place a plausible-looking derivation gets a wrong answer
  SHA-512  frac(sqrt(prime i)) * 2^64,  primes 1..8
  SHA-384  frac(sqrt(prime i)) * 2^64,  primes 9..16

-- and, for the two truncated variants, from the construction in section
5.3.6: SHA-512 with every IV word xored by 0xa5a5a5a5a5a5a5a5, applied to the
ASCII string "SHA-512/224" or "SHA-512/256".  That last one is done with a
SHA-512 written here in Python, independent of the C, and the Python one is
itself checked against hashlib first.

`python3 tools/genk.py emit` prints the two K tables as C.
"""
import hashlib
import re
import struct
import sys
from decimal import Decimal, getcontext

getcontext().prec = 120
M64 = (1 << 64) - 1


def primes(n):
    out, x = [], 2
    while len(out) < n:
        if all(x % p for p in out if p * p <= x):
            out.append(x)
        x += 1
    return out


def frac(d, bits):
    return int((d - int(d)) * (1 << bits))


def root(p, k):
    return Decimal(p) ** (Decimal(1) / Decimal(k))


P = primes(80)
K256 = [frac(root(p, 3), 32) for p in P[:64]]
K512 = [frac(root(p, 3), 64) for p in P[:80]]
IV256 = [frac(root(p, 2), 32) for p in P[:8]]
# Section 5.3.2: the low half of the 64-bit fraction, not the high half.
IV224 = [frac(root(p, 2), 64) & 0xFFFFFFFF for p in P[8:16]]
IV512 = [frac(root(p, 2), 64) for p in P[:8]]
IV384 = [frac(root(p, 2), 64) for p in P[8:16]]


def sha512_with_iv(iv, msg):
    """SHA-512 from the spec, so that a non-standard IV can be used.  FIPS
    180-4 section 5.3.6 defines the SHA-512/t IVs this way and no library
    exposes it."""
    h = list(iv)
    m = msg + b"\x80"
    while len(m) % 128 != 112:
        m += b"\x00"
    m += struct.pack(">QQ", 0, len(msg) * 8)

    def rr(x, n):
        return ((x >> n) | (x << (64 - n))) & M64

    for off in range(0, len(m), 128):
        w = list(struct.unpack(">16Q", m[off:off + 128]))
        for t in range(16, 80):
            x, y = w[t - 15], w[t - 2]
            s0 = rr(x, 1) ^ rr(x, 8) ^ (x >> 7)
            s1 = rr(y, 19) ^ rr(y, 61) ^ (y >> 6)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & M64)
        a, b, c, d, e, f, g, hh = h
        for t in range(80):
            S1 = rr(e, 14) ^ rr(e, 18) ^ rr(e, 41)
            t1 = (hh + S1 + ((e & f) ^ (~e & M64 & g)) + K512[t] + w[t]) & M64
            S0 = rr(a, 28) ^ rr(a, 34) ^ rr(a, 39)
            t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) & M64
            hh, g, f, e = g, f, e, (d + t1) & M64
            d, c, b, a = c, b, a, (t1 + t2) & M64
        h = [(x + y) & M64 for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return h


def truncated_iv(t):
    seed = [x ^ 0xA5A5A5A5A5A5A5A5 for x in IV512]
    return sha512_with_iv(seed, ("SHA-512/%d" % t).encode())


def selfcheck():
    """The Python SHA-512 must agree with hashlib before it is used to derive
    anything, and each derived IV must reproduce hashlib's digest of "abc"."""
    want = list(struct.unpack(">8Q", hashlib.sha512(b"abc").digest()))
    assert sha512_with_iv(IV512, b"abc") == want, "python sha512 is wrong"
    for t in (224, 256):
        iv = truncated_iv(t)
        d = struct.pack(">8Q", *sha512_with_iv(iv, b"abc"))[:t // 8]
        ref = hashlib.new("sha512_%d" % t, b"abc").digest()
        assert d == ref, "derived SHA-512/%d IV is wrong" % t


def emit():
    print("static const uint32_t K256[64] = {")
    for i in range(0, 64, 4):
        print("\t" + " ".join("0x%08xu," % v for v in K256[i:i + 4]))
    print("};")
    print("static const uint64_t K512[80] = {")
    for i in range(0, 80, 2):
        print("\t" + " ".join("0x%016xull," % v for v in K512[i:i + 2]))
    print("};")


def grab(src, pattern, count):
    m = re.search(pattern, src, re.S)
    if not m:
        sys.exit("genk: cannot find %s in the source" % pattern)
    vals = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", m.group(1))]
    if len(vals) != count:
        sys.exit("genk: expected %d constants, found %d" % (count, len(vals)))
    return vals


def check(path):
    selfcheck()
    src = open(path).read()
    got_k256 = grab(src, r"K256\[64\] = \{(.*?)\};", 64)
    got_k512 = grab(src, r"K512\[80\] = \{(.*?)\};", 80)
    got_iv = grab(src, r"IV\[SHA2_NALG\]\[8\] = \{(.*?)\n\};", 48)
    want_iv = IV224 + IV256 + IV384 + IV512 + \
        truncated_iv(224) + truncated_iv(256)
    bad = 0
    for name, got, want in (("K256", got_k256, K256),
                            ("K512", got_k512, K512),
                            ("IV", got_iv, want_iv)):
        if got == want:
            print("ok - %s in %s matches the FIPS 180-4 definition (%d "
                  "constants)" % (name, path, len(want)))
        else:
            n = sum(a != b for a, b in zip(got, want))
            print("not ok - %s in %s: %d of %d constants differ from the "
                  "derived value" % (name, path, n, len(want)))
            bad += 1
    return bad


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "emit":
        selfcheck()
        emit()
    elif len(sys.argv) == 3 and sys.argv[1] == "check":
        sys.exit(1 if check(sys.argv[2]) else 0)
    else:
        sys.exit("usage: genk.py emit | check sha2.c")
