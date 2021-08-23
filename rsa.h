#include "hash_info.h"

struct RSA_ASN1_template {
	const uint8_t *data;
	size_t size;
};

enum pkey_hash_algo {
	PKEY_HASH_MD4,
	PKEY_HASH_MD5,
	PKEY_HASH_SHA1,
	PKEY_HASH_RIPE_MD_160,
	PKEY_HASH_SHA256,
	PKEY_HASH_SHA384,
	PKEY_HASH_SHA512,
	PKEY_HASH_SHA224,
	PKEY_HASH__LAST
};

extern const struct RSA_ASN1_template RSA_ASN1_templates[PKEY_HASH__LAST];
