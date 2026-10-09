/* t/tst.c -- every C-side test in one program, picked by subcommand.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   tst unit               assertions that need no downloaded data
 *   tst sweep ALG N        digest of pat(L) for every L in 0..N, one per line
 */
#include "../sha2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails;

/* The sweep input: byte i is i*31+7.  Defined here and recomputed
 * independently in t/diff.py, so neither side can be fed the other's data. */
static void pattern(unsigned char *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		p[i] = (unsigned char)(i * 31 + 7);
}

static void hex(const unsigned char *d, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", d[i]);
}

static void ck(const char *what, const char *got, const char *want)
{
	if (!strcmp(got, want)) {
		printf("ok - %s\n", what);
	} else {
		printf("not ok - %s\n  got  %s\n  want %s\n", what, got, want);
		fails++;
	}
}

/* Hash msg and compare against a hex digest. */
static void ckh(enum sha2_alg a, const void *msg, size_t len,
		const char *want, const char *what)
{
	unsigned char d[SHA2_DIGEST_MAX];
	char g[2 * SHA2_DIGEST_MAX + 1];
	sha2(a, msg, len, d);
	hex(d, sha2_digest_size(a), g);
	ck(what, g, want);
}

/* The lengths where the length field stops fitting in the current block.
 * For a 64-byte block that is 56: 55 bytes plus the 0x80 byte leaves exactly
 * 8 free, 56 leaves 7 and the padding has to spill into a second block.  119
 * and 120 are the same boundary one block later, and are also the SHA-512
 * boundary minus 8, which is why they are here for both widths.  Digests from
 * CPython hashlib; t/diff.py rederives the same answers from a different
 * input, so these are a second, independent copy rather than the only one.
 */
static void boundaries(void)
{
	static const struct { int n; const char *md; } v[] = {
		{ 55, "9f4390f8d30c2dd92ec9f095b65e2b9a"
		      "e9b0a925a5258e241c9f1e910f734318" },
		{ 56, "b35439a4ac6f0948b6d6f9e3c6af0f5f"
		      "590ce20f1bde7090ef7970686ec6738a" },
		{ 63, "7d3e74a05d7db15bce4ad9ec0658ea98"
		      "e3f06eeecf16b4c6fff2da457ddc2f34" },
		{ 64, "ffe054fe7ae0cb6dc65c3af9b61d5209"
		      "f439851db43d0ba5997337df154668eb" },
		{ 65, "635361c48bb9eab14198e76ea8ab7f1a"
		      "41685d6ad62aa9146d301d4f17eb0ae0" },
		{ 119, "31eba51c313a5c08226adf18d4a359cf"
		       "dfd8d2e816b13f4af952f7ea6584dcfb" },
		{ 120, "2f3d335432c70b580af0e8e1b3674a7c"
		       "020d683aa5f73aaaedfdc55af904c21c" },
		{ 127, "c57e9278af78fa3cab38667bef4ce29d"
		       "783787a2f731d4e12200270f0c32320a" },
		{ 128, "6836cf13bac400e9105071cd6af47084"
		       "dfacad4e5e302c94bfed24e013afb73e" },
		{ 129, "c12cb024a2e5551cca0e08fce8f1c5e3"
		       "14555cc3fef6329ee994a3db752166ae" },
	};
	char what[64];
	unsigned char a[160];
	memset(a, 'a', sizeof a);
	for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
		sprintf(what, "padding boundary: sha256(%d * 'a')", v[i].n);
		ckh(SHA2_256, a, (size_t)v[i].n, v[i].md, what);
	}
}

/* The contract for reusing a context, which sha2.h states and hashlib shares:
 * final() does not consume the context, so calling it twice gives the same
 * digest, and update() after final() continues the same message. */
static void restate(void)
{
	unsigned char d1[SHA2_DIGEST_MAX], d2[SHA2_DIGEST_MAX];
	unsigned char ref[SHA2_DIGEST_MAX];
	char g[2 * SHA2_DIGEST_MAX + 1], w[2 * SHA2_DIGEST_MAX + 1];
	struct sha2_ctx c;

	for (int a = 0; a < SHA2_NALG; a++) {
		size_t n = sha2_digest_size(a);
		sha2_init(&c, a);
		sha2_update(&c, "abc", 3);
		sha2_final(&c, d1);
		sha2_final(&c, d2);
		hex(d1, n, g);
		hex(d2, n, w);
		sprintf(g + 2 * n, " (%s)", sha2_name(a));
		sprintf(w + 2 * n, " (%s)", sha2_name(a));
		ck("final() twice gives the same digest", g, w);

		sha2_update(&c, "def", 3);
		sha2_final(&c, d1);
		sha2(a, "abcdef", 6, ref);
		hex(d1, n, g);
		hex(ref, n, w);
		sprintf(g + 2 * n, " (%s)", sha2_name(a));
		sprintf(w + 2 * n, " (%s)", sha2_name(a));
		ck("update() after final() continues the message", g, w);
	}
}

static void unit(void)
{
	/* FIPS 180-4 appendix B: the published worked examples. */
	ckh(SHA2_256, "abc", 3,
	    "ba7816bf8f01cfea414140de5dae2223"
	    "b00361a396177a9cb410ff61f20015ad", "FIPS 180-4 B.1 sha256(abc)");
	ckh(SHA2_256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	    56, "248d6a61d20638b8e5c026930c3e6039"
		"a33ce45964ff2167f6ecedd419db06c1",
	    "FIPS 180-4 B.2 sha256(56 bytes)");
	/* The empty input, which is the one case a hand-written padding loop
	 * most often gets wrong. */
	ckh(SHA2_256, "", 0,
	    "e3b0c44298fc1c149afbf4c8996fb924"
	    "27ae41e4649b934ca495991b7852b855", "sha256(empty)");

	boundaries();
	restate();
}

static void sweep(enum sha2_alg a, size_t maxlen)
{
	unsigned char *p = malloc(maxlen + 1), d[SHA2_DIGEST_MAX];
	char g[2 * SHA2_DIGEST_MAX + 1];
	if (!p)
		exit(2);
	pattern(p, maxlen + 1);
	for (size_t n = 0; n <= maxlen; n++) {
		sha2(a, p, n, d);
		hex(d, sha2_digest_size(a), g);
		printf("%zu %s\n", n, g);
	}
	free(p);
}

static enum sha2_alg arg_alg(const char *s)
{
	enum sha2_alg a;
	if (sha2_by_name(s, &a)) {
		fprintf(stderr, "tst: unknown algorithm %s\n", s);
		exit(2);
	}
	return a;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: tst unit | sweep ALG N\n");
		return 2;
	}
	if (!strcmp(argv[1], "unit"))
		unit();
	else if (!strcmp(argv[1], "sweep") && argc == 4)
		sweep(arg_alg(argv[2]), strtoul(argv[3], NULL, 0));
	else {
		fprintf(stderr, "tst: unknown subcommand %s\n", argv[1]);
		return 2;
	}
	return fails != 0;
}
