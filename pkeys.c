
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dirent.h> 
#include <sys/types.h>
#include <ctype.h>
#include "config.h"
#if HAVE_OPENSSL_SHA_H
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#endif
#include <asm/byteorder.h>
#include "test.h"
#include "hash_info.h"
#include "list.h"
#include "debug.h"

struct public_key_entry {
	struct list_head list;
	uint8_t keyid[8];
	char name[9];
	RSA *key;
};

LIST_HEAD(pkey_list);


static struct public_key_entry *pkey_alloc()
{
	struct public_key_entry *entry;

	entry = malloc(sizeof(struct public_key_entry));
	return entry;
}

static void pkey_add(struct public_key_entry *entry)
{
	list_add_tail(&entry->list, &pkey_list);
}

#if HAVE_OPENSSL_SHA_H
static int calc_keyid_v2(uint32_t *keyid, char *str, RSA *key)
{
	uint8_t sha1[SHA_DIGEST_LENGTH];
	unsigned char *pkey = NULL;
	int len;

	len = i2d_RSAPublicKey(key, &pkey);
	if (len < 0)
		return -EINVAL;

	SHA1(pkey, len, sha1);

	/* sha1[12 - 19] is exactly keyid from gpg file */
	memcpy(keyid, sha1 + 16, 4);
	sprintf(str, "%x ", __be32_to_cpup(keyid));

	free(pkey);
	return 0;
}

static RSA *read_pub_key(const char *keyfile)
{
	FILE *fp;
	RSA *key = NULL;
	X509 *crt = NULL;
	EVP_PKEY *pkey = NULL;

	fp = fopen(keyfile, "r");
	if (!fp) {
		log_err("Unable to open keyfile %s\n", keyfile);
		return NULL;
	}

	crt = d2i_X509_fp(fp, NULL);
	if (!crt) {
		log_err("d2i_X509_fp() failed\n");
		goto out;
	}
	pkey = X509_extract_key(crt);
	if (!pkey) {
		log_err("X509_extract_key() failed\n");
		goto out;
	}
	key = EVP_PKEY_get1_RSA(pkey);

	if (!key)
		log_err("PEM_read_RSA_PUBKEY() failed\n");

out:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (crt)
		X509_free(crt);
	fclose(fp);
	return key;
}

RSA *pkey_find(uint8_t *keyid)
{
	struct public_key_entry *entry = NULL;
	int found = 0;

	list_for_each_entry(entry, &pkey_list, list) {
		if (memcmp(entry->keyid, keyid, sizeof *keyid) == 0) {
			//printf(" pkey_list: name field %s \n", entry->name);
			found = 1;
			break;
		}
	}
	return (!found ? NULL : entry->key);
}

int pkey_init(char *path)
{
	struct public_key_entry *entry;
  	struct dirent *d;
	DIR *dir;
	int err = -EINVAL;

	if (!path)
		goto out;

	dir = opendir(path);
	if (!dir)
		goto out;

	while ((d = readdir(dir)) != NULL) {
		char *pathname;

		if (d->d_type != DT_REG)
			continue;

		err = -ENOMEM;
		entry = pkey_alloc();
		if (!entry)
			goto out;
	
		pathname = malloc(strlen(path) + strlen(d->d_name) + 1);
		if (!pathname)
			goto out;

		strcpy(pathname, path);
		strcat(pathname, d->d_name);

		entry->key = read_pub_key(pathname);
		if (!entry->key) {
			err = -EINVAL;
			goto out;
		}

		err = calc_keyid_v2((uint32_t *)entry->keyid, entry->name,
				     entry->key);
		if (err < 0) {
			printf("%s: invalid public key\n", pathname);
			goto out;
		}

		printf("%s %s\n",entry->name, pathname);
		pkey_add(entry);
		err = 0;
		free(pathname);
	}
	closedir(dir);
out:
	return err;
}
#endif
