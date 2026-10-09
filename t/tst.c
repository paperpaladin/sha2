/* t/tst.c -- every C-side test in one program, picked by subcommand.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 *   tst unit               assertions that need no downloaded data
 *   tst sweep ALG N        digest of pat(L) for every L in 0..N, one per line
 *   tst hex ALG            digest of stdin, read in 64kB chunks
 *   tst chunks ALG SEED    digest of stdin, fed in pseudorandom chunk sizes
 *   tst hmacsweep ALG N    hmac over pat() keys of every length 0..N
 *   tst pbkdf2 ALG C N     pbkdf2 with RFC 6070's inputs, C iters, N bytes
 *   tst cavp ALG FILE      NIST CAVP ShortMsg/LongMsg .rsp file
 */
#include "../sha2.h"
#include <ctype.h>
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
	/* The same boundary for the 128-byte block: 111 bytes plus 0x80 leaves
	 * exactly 16 free for the 128-bit length, 112 leaves 15 and spills. */
	static const struct { int n; const char *md; } w[] = {
		{ 111, "fa9121c7b32b9e01733d034cfc78cbf6"
		       "7f926c7ed83e82200ef8681819692176"
		       "0b4beff48404df811b95382827446167"
		       "3c68d04e297b0eb7b2b4d60fc6b566a2" },
		{ 112, "c01d080efd492776a1c43bd23dd99d0a"
		       "2e626d481e16782e75d54c2503b5dc32"
		       "bd05f0f1ba33e568b88fd2d970929b71"
		       "9ecbb152f58f130a407c8830604b70ca" },
		{ 119, "130396a75cb483f2eee8c56d8a668bb3"
		       "d2641f5243212c0bee2bd33da096ad9e"
		       "b8179fe18f9eaacf76e09fae9de4c3f1"
		       "4ba13341e345be05bf76c182cc3468cb" },
		{ 120, "f241de612b01aa2fa3cf01531d2a8e5e"
		       "17fc761dfd48a704a834a47f57d6eade"
		       "7804ecc39be42fdef16ec6adeaf7c01c"
		       "2fd0c4cc97d3860907cfa4a3b36d0c05" },
		{ 127, "828613968b501dc00a97e08c73b118aa"
		       "8876c26b8aac93df128502ab360f91ba"
		       "b50a51e088769a5c1eff4782ace147dc"
		       "e3642554199876374291f5d921629502" },
		{ 128, "b73d1929aa615934e61a871596b3f3b3"
		       "3359f42b8175602e89f7e06e5f658a24"
		       "3667807ed300314b95cacdd579f3e33a"
		       "bdfbe351909519a846d465c59582f321" },
		{ 129, "4f681e0bd53cda4b5a2041cc8a06f2ea"
		       "bde44fb16c951fbd5b87702f07aeab61"
		       "1565b19c47fde30587177ebb852e3971"
		       "bbd8d3fd30da18d71037dfbd98420429" },
		{ 239, "52c853cb8d907f3d4d6b889beb027985"
		       "d7c273486d75f8baf26f80d24e90c74c"
		       "6c3de3e22131582380a7d14d43f2941a"
		       "31385439cd6ddc469f628015e50bf286" },
		{ 240, "4c296d90c61052a62ffb1dd196f1b7b0"
		       "9373b1f93e71836baebf89690546b759"
		       "5684dbe9467a8e484fa0d1094272b434"
		       "4a7c24f5fee8daedeb0bf549c985ab5f" },
	};
	char what[64];
	unsigned char a[256];
	memset(a, 'a', sizeof a);
	for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
		sprintf(what, "padding boundary: sha256(%d * 'a')", v[i].n);
		ckh(SHA2_256, a, (size_t)v[i].n, v[i].md, what);
	}
	for (size_t i = 0; i < sizeof w / sizeof *w; i++) {
		sprintf(what, "padding boundary: sha512(%d * 'a')", w[i].n);
		ckh(SHA2_512, a, (size_t)w[i].n, w[i].md, what);
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

/* RFC 4231 test cases 1 to 7, all four algorithms the RFC covers.  Case 5 is
 * the truncation case; truncating the tag is the caller's job, so the full
 * tag is checked here.  Cases 6 and 7 use a 131-byte key, longer than both
 * block sizes, which is the step (hash the key first) that implementations
 * get wrong.  Case 2's key is 4 bytes and case 4's is 25, so keys shorter
 * than, equal to (the 64-byte sweep in t/diff.py) and longer than the block
 * size are all covered.
 */
static void hmac_rfc4231(void)
{
	static const struct {
		int n;
		enum sha2_alg alg;
		const char *key;
		size_t klen;
		const char *msg;
		size_t mlen;
		const char *mac;
	} v[] = {
		{ 1, SHA2_224, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
		  "896fb1128abbdf196832107cd49df33f"
		  "47b4b1169912ba4f53684b22" },
		{ 1, SHA2_256, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
		  "b0344c61d8db38535ca8afceaf0bf12b"
		  "881dc200c9833da726e9376c2e32cff7" },
		{ 1, SHA2_384, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
		  "afd03944d84895626b0825f4ab46907f"
		  "15f9dadbe4101ec682aa034c7cebc59c"
		  "faea9ea9076ede7f4af152e8b2fa9cb6" },
		{ 1, SHA2_512, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
		  "87aa7cdea5ef619d4ff0b4241a1d6cb0"
		  "2379f4e2ce4ec2787ad0b30545e17cde"
		  "daa833b7d6b8a702038b274eaea3f4e4"
		  "be9d914eeb61f1702e696c203a126854" },
		{ 2, SHA2_224, "\x4a\x65\x66\x65", 4, "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
		  "a30e01098bc6dbbf45690f3a7e9e6d0f"
		  "8bbea2a39e6148008fd05e44" },
		{ 2, SHA2_256, "\x4a\x65\x66\x65", 4, "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
		  "5bdcc146bf60754e6a042426089575c7"
		  "5a003f089d2739839dec58b964ec3843" },
		{ 2, SHA2_384, "\x4a\x65\x66\x65", 4, "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
		  "af45d2e376484031617f78d2b58a6b1b"
		  "9c7ef464f5a01b47e42ec3736322445e"
		  "8e2240ca5e69e2c78b3239ecfab21649" },
		{ 2, SHA2_512, "\x4a\x65\x66\x65", 4, "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
		  "164b7a7bfcf819e2e395fbe73b56e0a3"
		  "87bd64222e831fd610270cd7ea250554"
		  "9758bf75c05a994a6d034f65f8f0e6fd"
		  "caeab1a34d4a6b4b636e070a38bce737" },
		{ 3, SHA2_224, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20, "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50,
		  "7fb3cb3588c6c1f6ffa9694d7d6ad264"
		  "9365b0c1f65d69d1ec8333ea" },
		{ 3, SHA2_256, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20, "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50,
		  "773ea91e36800e46854db8ebd09181a7"
		  "2959098b3ef8c122d9635514ced565fe" },
		{ 3, SHA2_384, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20, "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50,
		  "88062608d3e6ad8a0aa2ace014c8a86f"
		  "0aa635d947ac9febe83ef4e55966144b"
		  "2a5ab39dc13814b94e3ab6e101a34f27" },
		{ 3, SHA2_512, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20, "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50,
		  "fa73b0089d56a284efb0f0756c890be9"
		  "b1b5dbdd8ee81a3655f83e33b2279d39"
		  "bf3e848279a722c806b485a47e67c807"
		  "b946a337bee8942674278859e13292fb" },
		{ 4, SHA2_224, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25, "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 50,
		  "6c11506874013cac6a2abc1bb382627c"
		  "ec6a90d86efc012de7afec5a" },
		{ 4, SHA2_256, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25, "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 50,
		  "82558a389a443c0ea4cc819899f2083a"
		  "85f0faa3e578f8077a2e3ff46729665b" },
		{ 4, SHA2_384, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25, "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 50,
		  "3e8a69b7783c25851933ab6290af6ca7"
		  "7a9981480850009cc5577c6e1f573b4e"
		  "6801dd23c4a7d679ccf8a386c674cffb" },
		{ 4, SHA2_512, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25, "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 50,
		  "b0ba465637458c6990e5a8c5f61d4af7"
		  "e576d97ff94b872de76f8050361ee3db"
		  "a91ca5c11aa25eb4d679275cc5788063"
		  "a5f19741120c4f2de2adebeb10a298dd" },
		{ 5, SHA2_224, "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20, "\x54\x65\x73\x74\x20\x57\x69\x74\x68\x20\x54\x72\x75\x6e\x63\x61\x74\x69\x6f\x6e", 20,
		  "0e2aea68a90c8d37c988bcdb9fca6fa8"
		  "099cd857c7ec4a1815cac54c" },
		{ 5, SHA2_256, "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20, "\x54\x65\x73\x74\x20\x57\x69\x74\x68\x20\x54\x72\x75\x6e\x63\x61\x74\x69\x6f\x6e", 20,
		  "a3b6167473100ee06e0c796c2955552b"
		  "fa6f7c0a6a8aef8b93f860aab0cd20c5" },
		{ 5, SHA2_384, "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20, "\x54\x65\x73\x74\x20\x57\x69\x74\x68\x20\x54\x72\x75\x6e\x63\x61\x74\x69\x6f\x6e", 20,
		  "3abf34c3503b2a23a46efc619baef897"
		  "f4c8e42c934ce55ccbae9740fcbc1af4"
		  "ca62269e2a37cd88ba926341efe4aeea" },
		{ 5, SHA2_512, "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20, "\x54\x65\x73\x74\x20\x57\x69\x74\x68\x20\x54\x72\x75\x6e\x63\x61\x74\x69\x6f\x6e", 20,
		  "415fad6271580a531d4179bc891d87a6"
		  "50188707922a4fbb36663a1eb16da008"
		  "711c5b50ddd0fc235084eb9d3364a145"
		  "4fb2ef67cd1d29fe6773068ea266e96b" },
		{ 6, SHA2_224, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74", 54,
		  "95e9a0db962095adaebe9b2d6f0dbce2"
		  "d499f112f2d2b7273fa6870e" },
		{ 6, SHA2_256, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74", 54,
		  "60e431591ee0b67f0d8a26aacbf5b77f"
		  "8e0bc6213728c5140546040f0ee37f54" },
		{ 6, SHA2_384, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74", 54,
		  "4ece084485813e9088d2c63a041bc5b4"
		  "4f9ef1012a2b588f3cd11f05033ac4c6"
		  "0c2ef6ab4030fe8296248df163f44952" },
		{ 6, SHA2_512, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74", 54,
		  "80b24263c7c1a3ebb71493c1dd7be8b4"
		  "9b46d1f41b4aeec1121b013783f8f352"
		  "6b56d037e05f2598bd0fd2215d6a1e52"
		  "95e64f73f63f0aec8b915a985d786598" },
		{ 7, SHA2_224, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x2e", 152,
		  "3a854166ac5d9f023f54d517d0b39dbd"
		  "946770db9c2b95c9f6f565d1" },
		{ 7, SHA2_256, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x2e", 152,
		  "9b09ffa71b942fcb27635fbcd5b0e944"
		  "bfdc63644f0713938a7f51535c3a35e2" },
		{ 7, SHA2_384, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x2e", 152,
		  "6617178e941f020d351e2f254e8fd32c"
		  "602420feb0b8fb9adccebb82461e99c5"
		  "a678cc31e799176d3860e6110c46523e" },
		{ 7, SHA2_512, "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x2e", 152,
		  "e37b6a775dc87dbaa4dfa9f96e5e3ffd"
		  "debd71f8867289865df5a32d20cdc944"
		  "b6022cac3c4982b10d5eeb55c3e4de15"
		  "134676fb6de0446065c97440fa8c6a58" },
	};
	unsigned char d[SHA2_DIGEST_MAX];
	char g[2 * SHA2_DIGEST_MAX + 1], what[64];

	for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
		sha2_hmac(v[i].alg, v[i].key, v[i].klen, v[i].msg, v[i].mlen, d);
		hex(d, sha2_digest_size(v[i].alg), g);
		sprintf(what, "RFC 4231 case %d: hmac-%s", v[i].n,
			sha2_name(v[i].alg));
		ck(what, g, v[i].mac);
	}
}

/* PBKDF2.
 *
 * RFC 6070's published vectors are PBKDF2-HMAC-SHA-1 and SHA-1 is not in this
 * library, so they cannot be checked here.  What is used instead:
 *
 *   - RFC 6070's *inputs* (password/salt/1, 2 and 4096 iterations, dkLen 20)
 *     with HMAC-SHA-256, where the expected values come from CPython
 *     hashlib.pbkdf2_hmac and openssl kdf -- see t/diff.py, which runs both.
 *   - RFC 7914 section 11, which publishes two PBKDF2-HMAC-SHA-256 vectors.
 *     Those are the authoritative, external ones, and they are below.
 */
static void pbkdf2_published(void)
{
	unsigned char dk[64];
	char g[129];

	/* RFC 7914 section 11, vector 1: P "passwd", S "salt", c 1, dkLen 64 */
	if (sha2_pbkdf2(SHA2_256, "passwd", 6, "salt", 4, 1, dk, 64))
		fails++;
	hex(dk, 64, g);
	ck("RFC 7914 PBKDF2-HMAC-SHA-256 c=1 dkLen=64", g,
	   "55ac046e56e3089fec1691c22544b605"
	   "f94185216dde0465e68b9d57c20dacbc"
	   "49ca9cccf179b645991664b39d77ef31"
	   "7c71b845b1e30bd509112041d3a19783");

	/* vector 2: P "Password", S "NaCl", c 80000, dkLen 64 */
	if (sha2_pbkdf2(SHA2_256, "Password", 8, "NaCl", 4, 80000, dk, 64))
		fails++;
	hex(dk, 64, g);
	ck("RFC 7914 PBKDF2-HMAC-SHA-256 c=80000 dkLen=64", g,
	   "4ddcd8f60b98be21830cee5ef22701f9"
	   "641a4418d04c0414aeff08876b34ab56"
	   "a1d425a1225833549adb841b51c9b317"
	   "6a272bdebba1d078478f62b397f33c8d");

	/* The two documented failure returns. */
	ck("pbkdf2 rejects iters == 0",
	   sha2_pbkdf2(SHA2_256, "p", 1, "s", 1, 0, dk, 1) ? "rejected" : "ok",
	   "rejected");
	ck("pbkdf2 accepts iters == 1",
	   sha2_pbkdf2(SHA2_256, "p", 1, "s", 1, 1, dk, 1) ? "rejected" : "ok",
	   "ok");
}

/* ------------------------------------------------------- NIST CAVP ---
 * The .rsp format: "Len = <bits>", "Msg = <hex>", "MD = <hex>", in that
 * order, with "[L = <bytes>]" headers and # comments.  Len = 0 carries
 * "Msg = 00" which means the empty message, not one zero byte -- a parser
 * that misses that scores one wrong answer and looks like an implementation
 * bug.
 *
 * The algorithm is not in the file (SHA-224 and SHA-512/224 both say
 * [L = 28]), so it comes from the caller, which reads it off the filename.
 */
static size_t hexdec(const char *s, unsigned char *out, size_t cap)
{
	size_t n = 0;
	for (;;) {
		int hi, lo;
		while (*s == ' ' || *s == '\t')
			s++;
		if (!isxdigit((unsigned char)s[0]) ||
		    !isxdigit((unsigned char)s[1]))
			break;
		hi = s[0] <= '9' ? s[0] - '0' : (s[0] | 32) - 'a' + 10;
		lo = s[1] <= '9' ? s[1] - '0' : (s[1] | 32) - 'a' + 10;
		if (n == cap)
			exit(2);
		out[n++] = (unsigned char)(hi * 16 + lo);
		s += 2;
	}
	return n;
}

static char *trim(char *s)
{
	size_t n = strlen(s);
	while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
		s[--n] = 0;
	return s;
}

static const char *base(const char *p)
{
	const char *s = strrchr(p, '/');
	return s ? s + 1 : p;
}

#define CAVP_LINE 65536
#define CAVP_MSG  32768

static void cavp(enum sha2_alg a, const char *path)
{
	static char line[CAVP_LINE];
	static unsigned char msg[CAVP_MSG];
	unsigned char d[SHA2_DIGEST_MAX];
	char g[2 * SHA2_DIGEST_MAX + 1];
	FILE *f = fopen(path, "r");
	long len = -1;
	size_t mlen = 0;
	int total = 0, bad = 0, firstbad = -1;

	if (!f) {
		printf("not ok - CAVP %s: cannot open\n", base(path));
		fails++;
		return;
	}
	while (fgets(line, sizeof line, f)) {
		if (!strncmp(line, "Len = ", 6)) {
			len = atol(line + 6);
		} else if (!strncmp(line, "Msg = ", 6)) {
			mlen = hexdec(line + 6, msg, sizeof msg);
			if (len == 0) {
				mlen = 0;	/* "Msg = 00" means empty */
			} else if (len < 0 || (size_t)len / 8 != mlen) {
				/* Declared bit length and decoded byte count
				 * must agree, or the parser is broken and a
				 * wrong answer would look like a hash bug. */
				printf("not ok - CAVP %s: Len = %ld but %zu"
				       " bytes of Msg\n", base(path), len, mlen);
				fails++;
				fclose(f);
				return;
			}
		} else if (!strncmp(line, "MD = ", 5)) {
			sha2(a, msg, mlen, d);
			hex(d, sha2_digest_size(a), g);
			total++;
			if (strcmp(g, trim(line + 5))) {
				if (firstbad < 0)
					firstbad = total;
				bad++;
			}
		}
	}
	fclose(f);
	/* A parser that matched nothing must not report a pass. */
	if (total == 0) {
		printf("not ok - CAVP %s: no vectors parsed\n", base(path));
		fails++;
		return;
	}
	printf("%s - CAVP %s (%s): %d/%d vectors",
	       bad ? "not ok" : "ok", base(path), sha2_name(a),
	       total - bad, total);
	if (bad)
		printf(", first failure at vector %d", firstbad);
	printf("\n");
	fails += bad != 0;
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

	/* FIPS 180-4 appendix C. */
	ckh(SHA2_512, "abc", 3,
	    "ddaf35a193617abacc417349ae204131"
	    "12e6fa4e89a97ea20a9eeee64b55d39a"
	    "2192992a274fc1a836ba3c23a3feebbd"
	    "454d4423643ce80e2a9ac94fa54ca49f", "FIPS 180-4 C.1 sha512(abc)");
	ckh(SHA2_512, "", 0,
	    "cf83e1357eefb8bdf1542850d66d8007"
	    "d620e4050b5715dc83f4a921d36ce9ce"
	    "47d0d13c5d85f2b0ff8318d2877eec2f"
	    "63b931bd47417a81a538327af927da3e", "sha512(empty)");

	boundaries();
	restate();
	hmac_rfc4231();
	pbkdf2_published();
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

/* xorshift64.  Only used to pick chunk sizes, so its quality is irrelevant;
 * what matters is that update() boundaries land all over the place and
 * include 0 and lengths either side of the block size. */
static uint64_t rs(uint64_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 7;
	*s ^= *s << 17;
	return *s;
}

/* Hash stdin.  chunk == 0 means fixed 64kB reads, otherwise the read size is
 * drawn from the PRNG each time (0 to 4096 inclusive, so zero-length updates
 * are exercised too). */
static void digest_stdin(enum sha2_alg a, uint64_t seed)
{
	unsigned char buf[65536], d[SHA2_DIGEST_MAX];
	char g[2 * SHA2_DIGEST_MAX + 1];
	struct sha2_ctx c;
	size_t n;

	sha2_init(&c, a);
	for (;;) {
		size_t want = seed ? (size_t)(rs(&seed) % 4097) : sizeof buf;
		if (want == 0) {
			sha2_update(&c, buf, 0);
			continue;
		}
		n = fread(buf, 1, want, stdin);
		if (n == 0)
			break;
		sha2_update(&c, buf, n);
	}
	sha2_final(&c, d);
	hex(d, sha2_digest_size(a), g);
	printf("%s\n", g);
}

/* The machine-readable half of restate(): three digests on three lines, for
 * t/diff.py to compare against hashlib doing the same three calls. */
static void restate_dump(enum sha2_alg a)
{
	unsigned char d[SHA2_DIGEST_MAX];
	char g[2 * SHA2_DIGEST_MAX + 1];
	struct sha2_ctx c;
	sha2_init(&c, a);
	sha2_update(&c, "abc", 3);
	for (int i = 0; i < 2; i++) {
		sha2_final(&c, d);
		hex(d, sha2_digest_size(a), g);
		printf("%s\n", g);
	}
	sha2_update(&c, "def", 3);
	sha2_final(&c, d);
	hex(d, sha2_digest_size(a), g);
	printf("%s\n", g);
}

/* HMAC with a pat() key of every length from 0 to maxlen, over a fixed
 * message.  The interesting lengths are 0, block size - 1, block size, and
 * block size + 1: at and above the block size the key has to be hashed. */
static void hmacsweep(enum sha2_alg a, size_t maxlen)
{
	unsigned char *k = malloc(maxlen + 1), d[SHA2_DIGEST_MAX];
	char g[2 * SHA2_DIGEST_MAX + 1];
	if (!k)
		exit(2);
	pattern(k, maxlen + 1);
	for (size_t n = 0; n <= maxlen; n++) {
		sha2_hmac(a, k, n, "the message", 11, d);
		hex(d, sha2_digest_size(a), g);
		printf("%zu %s\n", n, g);
	}
	free(k);
}

/* RFC 6070's inputs ("password", "salt"), any iteration count and length, for
 * t/diff.py to put to hashlib and openssl. */
static void pbkdf2_dump(enum sha2_alg a, unsigned long iters, size_t dklen)
{
	unsigned char dk[256];
	char g[513];
	if (dklen > sizeof dk ||
	    sha2_pbkdf2(a, "password", 8, "salt", 4, (uint32_t)iters, dk, dklen))
		exit(2);
	hex(dk, dklen, g);
	printf("%s\n", g);
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
		fprintf(stderr, "usage: tst unit | sweep ALG N | hex ALG"
			" | chunks ALG SEED\n");
		return 2;
	}
	if (!strcmp(argv[1], "unit"))
		unit();
	else if (!strcmp(argv[1], "sweep") && argc == 4)
		sweep(arg_alg(argv[2]), strtoul(argv[3], NULL, 0));
	else if (!strcmp(argv[1], "cavp") && argc == 4)
		cavp(arg_alg(argv[2]), argv[3]);
	else if (!strcmp(argv[1], "pbkdf2") && argc == 5)
		pbkdf2_dump(arg_alg(argv[2]), strtoul(argv[3], NULL, 0),
			    strtoul(argv[4], NULL, 0));
	else if (!strcmp(argv[1], "hmacsweep") && argc == 4)
		hmacsweep(arg_alg(argv[2]), strtoul(argv[3], NULL, 0));
	else if (!strcmp(argv[1], "restate") && argc == 3)
		restate_dump(arg_alg(argv[2]));
	else if (!strcmp(argv[1], "hex") && argc == 3)
		digest_stdin(arg_alg(argv[2]), 0);
	else if (!strcmp(argv[1], "chunks") && argc == 4)
		digest_stdin(arg_alg(argv[2]), strtoull(argv[3], NULL, 0) | 1);
	else {
		fprintf(stderr, "tst: unknown subcommand %s\n", argv[1]);
		return 2;
	}
	return fails != 0;
}
