#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "config.h"
#include <asm/byteorder.h>
#if HAVE_OPENSSL_SHA_H
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif
#include <ctype.h>

#include "test.h"
#include "hash_info.h"
#include "rsa.h"
#include "list.h"
#include "pkeys.h"
#include "debug.h"

/*
 * signature format v2 - for using with asymmetric keys
 */
struct signature_v2_hdr {
	uint8_t version;	/* signature format version */
	uint8_t	hash_algo;	/* Digest algorithm [enum pkey_hash_algo] */
	uint32_t keyid;		/* IMA key identifier - not X509/PGP specific*/
	uint16_t sig_size;	/* signature size */
	uint8_t sig[0];		/* signature payload */
} __attribute__ ((packed));


static int verify_hash_v2(const unsigned char *hash, u_int32_t size,
			  unsigned char *sig, u_int32_t siglen, RSA *key)
{
	int err, len;
	unsigned char out[1024];
	struct signature_v2_hdr *hdr = (struct signature_v2_hdr *)sig;
	const struct RSA_ASN1_template *asn1;

	err = RSA_public_decrypt(siglen - sizeof(*hdr), sig + sizeof(*hdr),
				 out, key, RSA_PKCS1_PADDING);
	if (err < 0) {
		print_info(" v2: RSA_public_decrypt() failed: %d\n", err);
		return -1;
	}

	len = err;
	asn1 = &RSA_ASN1_templates[hdr->hash_algo];
	if (len < asn1->size || memcmp(out, asn1->data, asn1->size))
		return -1;

	len -= asn1->size;
	if (len != size || memcmp(out + asn1->size, hash, len))
		return -1;
	return 0;
}

int verify_signature_v2(char *bufp,  u_int32_t field_len,
		        char *digest, u_int32_t digest_len)
{
	RSA *key;
	char name[9];
	int err = 0;

	if (*bufp != 0x03) {
		print_info(" : unsigned ");
		return 0;
	}

	key = pkey_find((uint8_t *)bufp + 3);
	if (!key) {
		get_keyid_name(name, bufp + 3);
		print_info(" keyid: %s missing-key", name);
		return -ENOKEY;
	} else {

		err = verify_hash_v2((unsigned char *)digest, digest_len,
		       (unsigned char *)bufp + 1, field_len -1, key);
		get_keyid_name(name, bufp + 3);
		print_info(" keyid: %s %s", name,
			    err == -1 ? "invalid signature" : "" );
	}
	return err;
} 
