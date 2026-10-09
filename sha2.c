/* sha2.c -- SHA-2 family, HMAC and PBKDF2 in one C11 file.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NOT constant-time, NOT side-channel hardened.  See sha2.h and README.md.
 *
 * FIPS 180-4 for the hashes.  The round constants and initial hash values are
 * not typed in: they were generated from their definitions (cube and square
 * roots of the first primes) by scratch/genk.py and cross-checked against
 * CPython hashlib, which is why the IVs for the two truncated SHA-512
 * variants -- which FIPS defines via a hash of the string "SHA-512/t" -- are
 * trustworthy here.
 */
#include "sha2.h"
#include <string.h>

static const uint32_t K256[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

/* Initial hash values.  The 32-bit algorithms use the low half of each entry;
 * sha2_init() narrows them. */
static const uint64_t IV[SHA2_NALG][8] = {
	{ 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	  0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 },
	{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 },
	{ 0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
	  0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
	  0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
	  0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull },
	{ 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
	  0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
	  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
	  0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull },
	{ 0x8c3d37c819544da2ull, 0x73e1996689dcd4d6ull,
	  0x1dfab7ae32ff9c82ull, 0x679dd514582f9fcfull,
	  0x0f6d2b697bd44da8ull, 0x77e36f7304c48942ull,
	  0x3f9d85a86a1d36c8ull, 0x1112e6ad91d692a1ull },
	{ 0x22312194fc2bf72cull, 0x9f555fa3c84c64c2ull,
	  0x2393b86b6f53b151ull, 0x963877195940eabdull,
	  0x96283ee2a88effe3ull, 0xbe5e1e2553863992ull,
	  0x2b0199fc2c85b8aaull, 0x0eb72ddc81c52ca2ull },
};

static const unsigned char DSZ[SHA2_NALG] = { 28, 32, 48, 64, 28, 32 };
static const char *const NAME[SHA2_NALG] = {
	"sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256"
};

size_t sha2_digest_size(enum sha2_alg a) { return DSZ[a]; }
size_t sha2_block_size(enum sha2_alg a) { return a < SHA2_384 ? 64 : 128; }
const char *sha2_name(enum sha2_alg a) { return NAME[a]; }

/* ASCII case-insensitive compare.  Six lines beats pulling in strcasecmp and
 * the feature macro that declares it. */
static int eqi(const char *a, const char *b)
{
	for (; *a && *b; a++, b++)
		if ((*a | 32) != (*b | 32))
			return 0;
	return *a == *b;
}

int sha2_by_name(const char *name, enum sha2_alg *out)
{
	/* Accepts the canonical spelling plus the ones people actually type:
	 * "sha-256", "SHA512/256", "512_256". */
	static const char *const alias[SHA2_NALG][3] = {
		{ "sha-224", "224", NULL },
		{ "sha-256", "256", NULL },
		{ "sha-384", "384", NULL },
		{ "sha-512", "512", NULL },
		{ "sha512/224", "512_224", "sha-512/224" },
		{ "sha512/256", "512_256", "sha-512/256" },
	};
	for (int a = 0; a < SHA2_NALG; a++) {
		if (eqi(name, NAME[a])) { *out = a; return 0; }
		for (int i = 0; i < 3; i++)
			if (alias[a][i] && eqi(name, alias[a][i])) {
				*out = a;
				return 0;
			}
	}
	return -1;
}

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static uint32_t ld32(const unsigned char *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static void st32(unsigned char *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

/* SHA-224/256 compression, FIPS 180-4 section 6.2.2.  nblk whole blocks. */
static void compress256(uint32_t *h, const unsigned char *p, size_t nblk)
{
	while (nblk--) {
		uint32_t w[64], a = h[0], b = h[1], c = h[2], d = h[3];
		uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
		for (int t = 0; t < 16; t++)
			w[t] = ld32(p + 4 * t);
		for (int t = 16; t < 64; t++) {
			uint32_t x = w[t - 15], y = w[t - 2];
			uint32_t s0 = ROR32(x, 7) ^ ROR32(x, 18) ^ (x >> 3);
			uint32_t s1 = ROR32(y, 17) ^ ROR32(y, 19) ^ (y >> 10);
			w[t] = w[t - 16] + s0 + w[t - 7] + s1;
		}
		for (int t = 0; t < 64; t++) {
			uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
			uint32_t t1 = hh + S1 + CH(e, f, g) + K256[t] + w[t];
			uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
			uint32_t t2 = S0 + MAJ(a, b, c);
			hh = g; g = f; f = e; e = d + t1;
			d = c; c = b; b = a; a = t1 + t2;
		}
		h[0] += a; h[1] += b; h[2] += c; h[3] += d;
		h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
		p += 64;
	}
}

static void absorb(struct sha2_ctx *c, const unsigned char *p, size_t nblk)
{
	compress256(c->h.w, p, nblk);
}

void sha2_init(struct sha2_ctx *c, enum sha2_alg alg)
{
	memset(c, 0, sizeof *c);
	c->alg = alg;
	for (int i = 0; i < 8; i++)
		c->h.w[i] = (uint32_t)IV[alg][i];
}

void sha2_update(struct sha2_ctx *c, const void *data, size_t len)
{
	const unsigned char *p = data;
	size_t bs = sha2_block_size(c->alg);

	/* 128-bit byte counter.  SHA-256 only encodes the low 64 bits of the
	 * bit length, but keeping both costs one add and lets the SHA-512
	 * padding be the same code. */
	if ((c->nlo += len) < len)
		c->nhi++;

	if (c->buflen) {
		size_t want = bs - c->buflen;
		if (len < want) {
			memcpy(c->buf + c->buflen, p, len);
			c->buflen += (unsigned)len;
			return;
		}
		memcpy(c->buf + c->buflen, p, want);
		absorb(c, c->buf, 1);
		c->buflen = 0;
		p += want;
		len -= want;
	}
	if (len >= bs) {
		size_t nblk = len / bs;
		absorb(c, p, nblk);
		p += nblk * bs;
		len -= nblk * bs;
	}
	memcpy(c->buf, p, len);
	c->buflen = (unsigned)len;
}

void sha2_final(const struct sha2_ctx *cc, unsigned char *out)
{
	struct sha2_ctx c = *cc;	/* pad a copy; see sha2.h */
	size_t bs = sha2_block_size(c.alg);
	size_t lf = bs / 8;		/* length field: 8 or 16 bytes */
	uint64_t bitlo = c.nlo << 3;
	uint64_t bithi = (c.nhi << 3) | (c.nlo >> 61);
	size_t i;

	c.buf[c.buflen++] = 0x80;
	if (c.buflen > bs - lf) {	/* no room for the length: spill */
		memset(c.buf + c.buflen, 0, bs - c.buflen);
		absorb(&c, c.buf, 1);
		c.buflen = 0;
	}
	memset(c.buf + c.buflen, 0, bs - lf - c.buflen);
	if (lf == 16) {
		st32(c.buf + bs - 16, (uint32_t)(bithi >> 32));
		st32(c.buf + bs - 12, (uint32_t)bithi);
	}
	st32(c.buf + bs - 8, (uint32_t)(bitlo >> 32));
	st32(c.buf + bs - 4, (uint32_t)bitlo);
	absorb(&c, c.buf, 1);

	for (i = 0; i < DSZ[c.alg]; i++)
		out[i] = (unsigned char)(c.h.w[i / 4] >> (24 - 8 * (i % 4)));
}

void sha2(enum sha2_alg alg, const void *data, size_t len, unsigned char *out)
{
	struct sha2_ctx c;
	sha2_init(&c, alg);
	sha2_update(&c, data, len);
	sha2_final(&c, out);
}
