/* sha2.c -- SHA-2 family, HMAC and PBKDF2 in one C11 file.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NOT constant-time, NOT side-channel hardened.  See sha2.h and README.md.
 *
 * FIPS 180-4 for the hashes.  The round constants and initial hash values are
 * not typed in: they are derived from their definitions (cube and square roots
 * of the first primes) by tools/genk.py, which also derives the IVs for the
 * two truncated SHA-512 variants the way FIPS 180-4 section 5.3.6 defines
 * them -- SHA-512 with its IV xored by 0xa5.. over the string "SHA-512/t".
 * `make test` runs `genk.py check sha2.c`, so all 192 constants below are
 * diffed against their definitions on every test run rather than trusted.
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

static const uint64_t K512[80] = {
	0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
	0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
	0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
	0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
	0xd807aa98a3030242ull, 0x12835b0145706fbeull,
	0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
	0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
	0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
	0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
	0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
	0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
	0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
	0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
	0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
	0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
	0x06ca6351e003826full, 0x142929670a0e6e70ull,
	0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
	0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
	0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
	0x81c2c92e47edaee6ull, 0x92722c851482353bull,
	0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
	0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
	0xd192e819d6ef5218ull, 0xd69906245565a910ull,
	0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
	0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
	0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
	0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
	0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
	0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
	0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
	0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
	0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
	0xca273eceea26619cull, 0xd186b8c721c0c207ull,
	0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
	0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
	0x113f9804bef90daeull, 0x1b710b35131c471bull,
	0x28db77f523047d84ull, 0x32caab7b40c72493ull,
	0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
	0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
	0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
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

/* shortcut: scalar C only, about 226 MB/s for the 32-bit core and 344 MB/s
 * for the 64-bit one on this machine.  SHA-NI (sha256rnds2) is roughly 4x for
 * SHA-256 and AVX2 multi-buffer more again, and both would mean runtime
 * dispatch, an intrinsics path and a second set of code to test against the
 * same vectors.  Upgrade path if throughput ever matters; it does not here.
 */
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

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint64_t ld64(const unsigned char *p)
{
	return (uint64_t)ld32(p) << 32 | ld32(p + 4);
}

/* SHA-384/512 compression, FIPS 180-4 section 6.4.2.  Same shape as
 * compress256 with 64-bit words, 80 rounds, and the six rotation constants
 * that differ. */
static void compress512(uint64_t *h, const unsigned char *p, size_t nblk)
{
	while (nblk--) {
		uint64_t w[80], a = h[0], b = h[1], c = h[2], d = h[3];
		uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
		for (int t = 0; t < 16; t++)
			w[t] = ld64(p + 8 * t);
		for (int t = 16; t < 80; t++) {
			uint64_t x = w[t - 15], y = w[t - 2];
			uint64_t s0 = ROR64(x, 1) ^ ROR64(x, 8) ^ (x >> 7);
			uint64_t s1 = ROR64(y, 19) ^ ROR64(y, 61) ^ (y >> 6);
			w[t] = w[t - 16] + s0 + w[t - 7] + s1;
		}
		for (int t = 0; t < 80; t++) {
			uint64_t S1 = ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41);
			uint64_t t1 = hh + S1 + CH(e, f, g) + K512[t] + w[t];
			uint64_t S0 = ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39);
			uint64_t t2 = S0 + MAJ(a, b, c);
			hh = g; g = f; f = e; e = d + t1;
			d = c; c = b; b = a; a = t1 + t2;
		}
		h[0] += a; h[1] += b; h[2] += c; h[3] += d;
		h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
		p += 128;
	}
}

static int wide(enum sha2_alg a) { return a >= SHA2_384; }

static void absorb(struct sha2_ctx *c, const unsigned char *p, size_t nblk)
{
	if (wide(c->alg))
		compress512(c->h.q, p, nblk);
	else
		compress256(c->h.w, p, nblk);
}

void sha2_init(struct sha2_ctx *c, enum sha2_alg alg)
{
	memset(c, 0, sizeof *c);
	c->alg = alg;
	for (int i = 0; i < 8; i++) {
		if (wide(alg))
			c->h.q[i] = IV[alg][i];
		else
			c->h.w[i] = (uint32_t)IV[alg][i];
	}
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

	/* Big-endian state, truncated to the digest length.  That truncation is
	 * the whole of SHA-224, SHA-384 and the two SHA-512/t variants beyond
	 * their differing IVs. */
	for (i = 0; i < DSZ[c.alg]; i++)
		out[i] = wide(c.alg)
			? (unsigned char)(c.h.q[i / 8] >> (56 - 8 * (i % 8)))
			: (unsigned char)(c.h.w[i / 4] >> (24 - 8 * (i % 4)));
}

void sha2(enum sha2_alg alg, const void *data, size_t len, unsigned char *out)
{
	struct sha2_ctx c;
	sha2_init(&c, alg);
	sha2_update(&c, data, len);
	sha2_final(&c, out);
}

/* ---------------------------------------------------------------- HMAC ---
 * RFC 2104.  The key is zero-padded to the block size, or hashed first if it
 * is longer than the block size -- which is the step implementations skip and
 * the reason RFC 4231 cases 6 and 7 use a 131-byte key.
 *
 * Not constant-time, and sha2_hmac_final() does not compare anything: a
 * caller checking a tag has to decide for itself whether it needs a
 * constant-time comparison.  This file will not do it for them.
 */
void sha2_hmac_init(struct sha2_hmac_ctx *c, enum sha2_alg alg,
		    const void *key, size_t keylen)
{
	unsigned char k[SHA2_BLOCK_MAX] = { 0 }, pad[SHA2_BLOCK_MAX];
	size_t bs = sha2_block_size(alg), i;

	if (keylen > bs)
		sha2(alg, key, keylen, k);
	else if (keylen)
		memcpy(k, key, keylen);

	for (i = 0; i < bs; i++)
		pad[i] = k[i] ^ 0x36;
	sha2_init(&c->in, alg);
	sha2_update(&c->in, pad, bs);

	for (i = 0; i < bs; i++)
		pad[i] = k[i] ^ 0x5c;
	sha2_init(&c->out, alg);
	sha2_update(&c->out, pad, bs);
}

void sha2_hmac_update(struct sha2_hmac_ctx *c, const void *data, size_t len)
{
	sha2_update(&c->in, data, len);
}

void sha2_hmac_final(const struct sha2_hmac_ctx *c, unsigned char *out)
{
	unsigned char d[SHA2_DIGEST_MAX];
	struct sha2_ctx o = c->out;

	sha2_final(&c->in, d);
	sha2_update(&o, d, sha2_digest_size(c->in.alg));
	sha2_final(&o, out);
}

void sha2_hmac(enum sha2_alg alg, const void *key, size_t keylen,
	       const void *msg, size_t msglen, unsigned char *out)
{
	struct sha2_hmac_ctx c;
	sha2_hmac_init(&c, alg, key, keylen);
	sha2_hmac_update(&c, msg, msglen);
	sha2_hmac_final(&c, out);
}

/* -------------------------------------------------------------- PBKDF2 ---
 * RFC 8018 section 5.2.  T_i = F(P, S, c, i), F being the xor of c
 * HMAC iterations starting from HMAC(P, S || INT_BE32(i)).
 *
 * The HMAC context with the password already absorbed is built once and
 * copied per iteration, which is the whole reason HMAC here is streaming:
 * neither the salt||counter concatenation nor the key schedule is redone.
 */
int sha2_pbkdf2(enum sha2_alg alg, const void *pw, size_t pwlen,
		const void *salt, size_t saltlen, uint32_t iters,
		unsigned char *out, size_t outlen)
{
	struct sha2_hmac_ctx base, c;
	unsigned char u[SHA2_DIGEST_MAX], t[SHA2_DIGEST_MAX], be[4];
	size_t hl = sha2_digest_size(alg), i, j, n;
	uint32_t blk;

	if (iters == 0)
		return -1;
	/* dkLen must fit in (2^32 - 1) blocks; the counter is 32 bits. */
	if (outlen / hl > 0xfffffffeu)
		return -1;

	sha2_hmac_init(&base, alg, pw, pwlen);
	for (blk = 1; outlen; blk++) {
		be[0] = (unsigned char)(blk >> 24);
		be[1] = (unsigned char)(blk >> 16);
		be[2] = (unsigned char)(blk >> 8);
		be[3] = (unsigned char)blk;

		c = base;
		sha2_hmac_update(&c, salt, saltlen);
		sha2_hmac_update(&c, be, 4);
		sha2_hmac_final(&c, u);
		memcpy(t, u, hl);

		for (i = 1; i < iters; i++) {
			c = base;
			sha2_hmac_update(&c, u, hl);
			sha2_hmac_final(&c, u);
			for (j = 0; j < hl; j++)
				t[j] ^= u[j];
		}

		n = outlen < hl ? outlen : hl;
		memcpy(out, t, n);
		out += n;
		outlen -= n;
	}
	return 0;
}

#ifdef SHA2_CLI
/* ----------------------------------------------------------------- CLI ---
 * sha2 [-a ALG] [FILE...] -- hashes stdin when given no files.  The output
 * format is coreutils', two spaces and the name, so that
 * `sha2 -a sha256 f | cmp - <(sha256sum f)` is a usable test and the output
 * feeds `sha256sum -c`.
 */
#include <stdio.h>

static int digest_stream(FILE *f, enum sha2_alg alg, const char *name)
{
	struct sha2_ctx c;
	unsigned char buf[65536], d[SHA2_DIGEST_MAX];
	size_t n, i;

	sha2_init(&c, alg);
	while ((n = fread(buf, 1, sizeof buf, f)) > 0)
		sha2_update(&c, buf, n);
	if (ferror(f)) {
		fprintf(stderr, "sha2: %s: read error\n", name);
		return -1;
	}
	sha2_final(&c, d);
	for (i = 0; i < sha2_digest_size(alg); i++)
		printf("%02x", d[i]);
	printf("  %s\n", name);
	return 0;
}

int main(int argc, char **argv)
{
	enum sha2_alg alg = SHA2_256;
	int i = 1, bad = 0;

	for (; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
		if (!strcmp(argv[i], "--"))
			{ i++; break; }
		if (!strcmp(argv[i], "-a") && i + 1 < argc) {
			if (sha2_by_name(argv[++i], &alg)) {
				fprintf(stderr, "sha2: unknown algorithm %s\n",
					argv[i]);
				return 2;
			}
			continue;
		}
		fprintf(stderr,
			"usage: sha2 [-a ALG] [FILE...]\n"
			"ALG: sha224 sha256 sha384 sha512 sha512-224"
			" sha512-256 (default sha256)\n"
			"Reads stdin when given no files, or for \"-\".\n");
		return strcmp(argv[i], "-h") ? 2 : 0;
	}

	if (i == argc)
		return digest_stream(stdin, alg, "-") ? 1 : 0;

	for (; i < argc; i++) {
		FILE *f;
		if (!strcmp(argv[i], "-")) {
			bad |= digest_stream(stdin, alg, "-") != 0;
			continue;
		}
		if (!(f = fopen(argv[i], "rb"))) {
			fprintf(stderr, "sha2: %s: cannot open\n", argv[i]);
			bad = 1;
			continue;
		}
		bad |= digest_stream(f, alg, argv[i]) != 0;
		fclose(f);
	}
	return bad;
}
#endif
