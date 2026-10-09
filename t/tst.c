/* t/tst.c -- every C-side test in one program, picked by subcommand.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   tst unit           assertions that need no downloaded data
 */
#include "../sha2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails;

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
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: tst unit\n");
		return 2;
	}
	if (!strcmp(argv[1], "unit"))
		unit();
	else {
		fprintf(stderr, "tst: unknown subcommand %s\n", argv[1]);
		return 2;
	}
	return fails != 0;
}
