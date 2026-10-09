/* sha2.h -- SHA-224/256/384/512/512-224/512-256, HMAC, PBKDF2.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * NOT SECURITY-CRITICAL CODE.  This implementation is not constant-time and
 * is not side-channel hardened: the HMAC comparison is left to the caller,
 * PBKDF2 does not lock or wipe memory, and nothing here resists timing or
 * cache analysis.  Do not use it where any of that matters.  It exists to be
 * correct against the published vectors, not to be safe against an attacker
 * who can measure it.
 */
#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

#define SHA2_BLOCK_MAX  128	/* SHA-512 family */
#define SHA2_DIGEST_MAX 64	/* SHA-512 */

enum sha2_alg {
	SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256,
	SHA2_NALG
};

/* Public so that it can live on the stack and be copied.  Copying a context
 * with plain assignment is supported and is how sha2_final() avoids
 * destroying it. */
struct sha2_ctx {
	union { uint32_t w[8]; uint64_t q[8]; } h;
	uint64_t nlo, nhi;		/* message length in bytes, 128-bit */
	unsigned char buf[SHA2_BLOCK_MAX];
	unsigned buflen;
	unsigned char alg;
};

void sha2_init(struct sha2_ctx *c, enum sha2_alg alg);
void sha2_update(struct sha2_ctx *c, const void *data, size_t len);

/* Takes a const context on purpose: finalising pads a copy, so final() may be
 * called twice for the same answer, and update() after final() continues the
 * same message.  This is CPython hashlib's contract, which makes it testable
 * against hashlib rather than against our own opinion. */
void sha2_final(const struct sha2_ctx *c, unsigned char *out);

void sha2(enum sha2_alg alg, const void *data, size_t len, unsigned char *out);

size_t sha2_digest_size(enum sha2_alg alg);
size_t sha2_block_size(enum sha2_alg alg);
const char *sha2_name(enum sha2_alg alg);
int sha2_by_name(const char *name, enum sha2_alg *out);	/* 0 on success */

#endif
