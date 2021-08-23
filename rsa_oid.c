/* RSA asymmetric public-key algorithm [RFC3447]
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include <stdint.h>
#include <sys/types.h>
#if HAVE_OPENSSL_SHA_H
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif
#include "rsa.h"

const char *const pkey_hash_algo[PKEY_HASH__LAST] = {
	[PKEY_HASH_MD4]		= "md4",
	[PKEY_HASH_MD5]		= "md5",
	[PKEY_HASH_SHA1]	= "sha1",
	[PKEY_HASH_RIPE_MD_160]	= "rmd160",
	[PKEY_HASH_SHA256]	= "sha256",
	[PKEY_HASH_SHA384]	= "sha384",
	[PKEY_HASH_SHA512]	= "sha512",
	[PKEY_HASH_SHA224]	= "sha224",
};

/*
 * Hash algorithm OIDs plus ASN.1 DER wrappings [RFC4880 sec 5.2.2].
 */
static const uint8_t RSA_digest_info_MD5[] = {
	0x30, 0x20, 0x30, 0x0C, 0x06, 0x08,
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, /* OID */
	0x05, 0x00, 0x04, 0x10
};

static const uint8_t RSA_digest_info_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x0E, 0x03, 0x02, 0x1A,
	0x05, 0x00, 0x04, 0x14
};

static const uint8_t RSA_digest_info_RIPE_MD_160[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x24, 0x03, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x14
};

static const uint8_t RSA_digest_info_SHA224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
	0x05, 0x00, 0x04, 0x1C
};

static const uint8_t RSA_digest_info_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x20
};

static const uint8_t RSA_digest_info_SHA384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
	0x05, 0x00, 0x04, 0x30
};

static const uint8_t RSA_digest_info_SHA512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
	0x05, 0x00, 0x04, 0x40
};

const struct RSA_ASN1_template RSA_ASN1_templates[PKEY_HASH__LAST] = {
#define _(X) { RSA_digest_info_##X, sizeof(RSA_digest_info_##X) }
	[PKEY_HASH_MD5]		= _(MD5),
	[PKEY_HASH_SHA1]	= _(SHA1),
	[PKEY_HASH_RIPE_MD_160]	= _(RIPE_MD_160),
	[PKEY_HASH_SHA256]	= _(SHA256),
	[PKEY_HASH_SHA384]	= _(SHA384),
	[PKEY_HASH_SHA512]	= _(SHA512),
	[PKEY_HASH_SHA224]	= _(SHA224),
#undef _
};
