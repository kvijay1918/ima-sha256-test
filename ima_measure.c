/*
 * Copyright (c) International Business Machines  Corp., 2008
 * Copyright (C) 2013 Politecnico di Torino, Italy
 *                    TORSEC group -- http://security.polito.it
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 * Roberto Sassu <roberto.sassu@polito.it>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_measure.c
 *
 * Calculate the SHA1 aggregate-pcr value based on the IMA runtime
 * binary measurements.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "config.h"
#include "test.h"
#include "ima_sigv2.h"

#if HAVE_OPENSSL_SHA_H
#include <openssl/sha.h>
#include <openssl/evp.h>
#endif
#include "debug.h"

//#define TCG_EVENT_NAME_LEN_MAX	255
#define TCG_EVENT_NAME_LEN_MAX	3000000
#define IMA_TEMPLATE_FIELD_ID_MAX_LEN	16
#define IMA_TEMPLATE_NUM_FIELDS_MAX	15
#define CRYPTO_MAX_ALG_NAME 64

#define IMA_TEMPLATE_IMA_NAME "ima"
#define IMA_TEMPLATE_IMA_FMT "d|n"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#define ERROR_ENTRY_PARSING 1
#define ERROR_FIELD_NOT_FOUND 2

extern int pkey_init(char *path);

char *TCID = "ima_measure";
int TST_TOTAL = 1;

int verbose;
static int verify, verify_sig;
static unsigned int no_sigs, unknown_keys, invalid_sigs;

#if HAVE_OPENSSL_SHA_H

static u_int8_t zero[SHA256_DIGEST_LENGTH];
static u_int8_t fox[SHA256_DIGEST_LENGTH];

static int display_digest(u_int8_t * digest, u_int32_t digestlen)
{
	int i;

	for (i = 0; i < digestlen; i++)
		print_info("%02x", (*(digest + i) & 0xff));
	return 0;
}

static int ima_eventdigest_parse(u_int8_t * buffer, u_int32_t buflen)
{
	return display_digest(buffer, SHA256_DIGEST_LENGTH);
}

static int ima_eventdigest_ng_parse(u_int8_t * buffer, u_int32_t buflen)
{
	char hash_algo[CRYPTO_MAX_ALG_NAME + 1] = { 0 };
	int algo_len = strlen((char *)buffer) - 1;/* format: algo + ':' + '\0' */
	const EVP_MD *md;
	int digest_len;

	if (algo_len > CRYPTO_MAX_ALG_NAME) {
		printf("Hash algorithm name too long\n");
		return ERROR_ENTRY_PARSING;
	}

	print_info("%s", buffer);

	memcpy(hash_algo, buffer, algo_len);
	md = EVP_get_digestbyname(hash_algo);
	if (md == NULL) {
		printf("Unknown hash algorithm '%s'\n", hash_algo);
		return ERROR_ENTRY_PARSING;
	}

	digest_len = EVP_MD_size(md);

	if (algo_len + 2 + digest_len != buflen) {
		printf("Field length mismatch, current: %d, expected: %d\n",
		       algo_len + 2 + digest_len, buflen);
		return ERROR_ENTRY_PARSING;
	}

	return display_digest(buffer + algo_len + 2, digest_len);
}

static int ima_parse_string(u_int8_t * buffer, u_int32_t buflen)
{
	char *str;

	/* some callers include the terminating null in the
 	 * buflen, others don't (eg. 'd').
 	 */
	str = calloc(buflen + 1, sizeof(u_int8_t));
	if (str == NULL) {
		printf("Out of memory\n");
		return -ENOMEM;
	}

	memcpy(str, buffer, buflen);
	print_info("%s", str);
	free(str);
	return 0;
}

static int ima_eventname_parse(u_int8_t * buffer, u_int32_t buflen)
{
	if (buflen > TCG_EVENT_NAME_LEN_MAX + 1) {
		printf("Event name too long\n");
		return -1;
	}

	return ima_parse_string(buffer, buflen);
}

static int ima_eventname_ng_parse(u_int8_t * buffer, u_int32_t buflen)
{
	return ima_parse_string(buffer, buflen);
}

static int ima_eventsig_parse(u_int8_t * buffer, u_int32_t buflen)
{
	return display_digest(buffer, buflen);
}

/* IMA template field definition */
struct ima_template_field {
	const char field_id[IMA_TEMPLATE_FIELD_ID_MAX_LEN];
	int (*field_parse) (u_int8_t * buffer, u_int32_t buflen);
};

/* IMA template descriptor definition */
struct ima_template_desc {
	char *name;
	char *fmt;
	int num_fields;
	struct ima_template_field **fields;
};

static struct ima_template_desc defined_templates[] = {
	{.name = IMA_TEMPLATE_IMA_NAME, .fmt = IMA_TEMPLATE_IMA_FMT},
	{.name = "ima-ng",.fmt = "d-ng|n-ng"},
	{.name = "ima-sig",.fmt = "d-ng|n-ng|sig"},
};

static struct ima_template_field supported_fields[] = {
	{.field_id = "d",.field_parse = ima_eventdigest_parse},
	{.field_id = "n",.field_parse = ima_eventname_parse},
	{.field_id = "d-ng",.field_parse = ima_eventdigest_ng_parse},
	{.field_id = "n-ng",.field_parse = ima_eventname_ng_parse},
	{.field_id = "sig",.field_parse = ima_eventsig_parse},
};

struct event {
	struct {
		u_int32_t pcr;
		u_int8_t digest[SHA256_DIGEST_LENGTH];
		u_int32_t name_len;
	} header;
	char name[TCG_EVENT_NAME_LEN_MAX + 1];
	struct ima_template_desc *template_desc; /* template descriptor */
	u_int32_t template_data_len;
	u_int8_t *template_data;	/* template related data */
};

static int parse_template_data(struct event *template)
{
	int offset = 0, result = 0;
	int i, j, is_ima_template;
	char *template_fmt, *template_fmt_ptr, *f;
	u_int32_t digest_len;
	u_int8_t *digest;

	is_ima_template = strcmp(template->name, "ima") == 0 ? 1 : 0;
	template->template_desc = NULL;

	for (i = 0; i < ARRAY_SIZE(defined_templates); i++) {
		if (strcmp(template->name,
			defined_templates[i].name) == 0) {
			template->template_desc = defined_templates + i;
			break;
		}
	}

	if (template->template_desc == NULL) {
		i = ARRAY_SIZE(defined_templates) - 1;
		template->template_desc = defined_templates + i;
		template->template_desc->fmt = template->name;
	}

	template_fmt = strdup(template->template_desc->fmt);
	if (template_fmt == NULL) {
		printf("Out of memory\n");
		return -ENOMEM;
	}

	template_fmt_ptr = template_fmt;
	for (i = 0; (f = strsep(&template_fmt_ptr, "|")) != NULL; i++) {
		struct ima_template_field *field = NULL;
		u_int32_t field_len = 0;

		for (j = 0; j < ARRAY_SIZE(supported_fields); j++) {
			if (!strcmp(f, supported_fields[j].field_id)) {
				field = supported_fields + j;
				break;
			}
		}

		if (field == NULL) {
			result = ERROR_FIELD_NOT_FOUND;
			printf("Field '%s' not supported\n", f);
			goto out;
		}

		if (is_ima_template && strcmp(f, "d") == 0)
			field_len = SHA256_DIGEST_LENGTH;
		else if (is_ima_template && strcmp(f, "n") == 0)
			field_len = strlen(template->template_data + offset);
		else {
			memcpy(&field_len, template->template_data + offset,
				 sizeof(u_int32_t));
			offset += sizeof(u_int32_t);
		}
		result = field->field_parse(template->template_data + offset,
					    field_len);
		if (result) {
			printf("Parsing of '%s' field failed, result: %d\n",
			       f, result);
			goto out;
		} 
		if (verify_sig && (strncmp(template->name, "ima-sig", 7) == 0)) {
			if (strcmp(f, "d-ng") == 0) {
				int algo_len;	 /* format: algo + ':' + '\0' */

				algo_len = strlen((char *)template->template_data
						+ offset) + 1;

				digest = template->template_data + offset + algo_len;	
				digest_len = field_len - algo_len;
			} else if (strcmp(f, "sig") == 0) {
				u_int8_t *field;

				field = template->template_data + offset;
				if (*field != 0x03)
					no_sigs++;
				else {
					int ret;

					ret = verify_signature_v2(field,
								  field_len,
								  digest,
								  digest_len);
					if (ret == -ENOKEY)
						unknown_keys++;
					else if (ret < 0)
						invalid_sigs++;
				}
			}
		}

		offset += field_len;
		print_info(" ");
	}
out:
	free(template_fmt);
	return result;
}

static int read_template_data(struct event *template, FILE *fp)
{
	int len, is_ima_template;

	is_ima_template = strcmp(template->name, "ima") == 0 ? 1 : 0;
	if (!is_ima_template) {
		fread(&template->template_data_len, sizeof(u_int32_t), 1, fp);
		len = template->template_data_len;
	} else {
		template->template_data_len = SHA256_DIGEST_LENGTH +
		    TCG_EVENT_NAME_LEN_MAX + 1;
		/*
		 * Read the digest only as the event name length
		 * is not known in advance.
		 */
		len = SHA256_DIGEST_LENGTH;
	}

	template->template_data = calloc(template->template_data_len,
					 sizeof(u_int8_t));
	if (template->template_data == NULL) {
		printf("ERROR: out of memory\n");
		return -ENOMEM;
	}

	fread(template->template_data, len, 1, fp);
	if (is_ima_template) {	/* finish 'ima' template data read */
		u_int32_t field_len;

		fread(&field_len, sizeof(u_int32_t), 1, fp);
		fread(template->template_data + SHA256_DIGEST_LENGTH,
		      field_len, 1, fp);
	}
	return 0;
}

/*
 * Calculate the sha1 hash of data
 */
static void calc_digest(u_int8_t *digest, int len, void *data )
{
	//SHA_CTX c;
SHA256_CTX c;

	/* Calc template hash for an ima entry */
	memset(digest, 0, sizeof *digest);
	/* SHA1_Init(&c);
	SHA1_Update(&c, data, len);
	SHA1_Final(digest, &c); */

	SHA256_Init(&c);
	SHA256_Update(&c, data, len);
	SHA256_Final(digest, &c);
}

static int verify_template_hash(struct event *template)
{
	int rc;

	rc = memcmp(fox, template->header.digest, sizeof fox);
	if (rc != 0) {
		u_int8_t digest[SHA256_DIGEST_LENGTH];
		memset(digest, 0, sizeof digest);
		calc_digest(digest, template->template_data_len,
			    template->template_data);
		rc = memcmp(digest, template->header.digest, sizeof digest);
		if (rc != 0)
			print_info("- %s\n", "failed");
	}
	return rc != 0 ? 1 : 0 ;
}

#endif

/*
 * ima_measurements.c - calculate the SHA1 aggregate-pcr value based
 * on the IMA runtime binary measurements.
 *
 * format: ima_measurement [--validate] [--verify] [--verbose]
 *
 * --validate: forces validation of the aggregrate pcr value
 * 	     for an invalidated PCR. Replace all entries in the
 * 	     runtime binary measurement list with 0x00 hash values,
 * 	     which indicate the PCR was invalidated, either for
 * 	     "a time of measure, time of use"(ToMToU) error, or a
 *	     file open for read was already open for write, with
 * 	     0xFF's hash value, when calculating the aggregate
 *	     pcr value.
 *
 * --verify: for all IMA template entries in the runtime binary
 * 	     measurement list, calculate the template hash value
 * 	     and compare it with the actual template hash value.
 * 	     
 * 	     For records with a signature, verify the file data
 * 	     hash against the file signature.
 *
 *	     Return the number of incorrect hash measurements
 *	     and signatures.
 *
 * --verbose: For all entries in the runtime binary measurement
 *	     list, display the template information.
 *
 * template info:  list #, PCR-register #, template hash, template name
 *	IMA info:  IMA hash, filename hint
 *
 * Ouput: displays the aggregate-pcr value
 * Return code: if verification enabled, returns number of verification
 * 		errors.
 */
int main(int argc, char *argv[])
{

#if HAVE_OPENSSL_SHA_H
	FILE *fp;
	struct event template;
	u_int8_t pcr[SHA256_DIGEST_LENGTH];
	int i, count = 0;
	int validate = 0;
	int hash_failed = 0;
	char *keypath = NULL;

	if (argc < 2) {
		printf("format: %s binary_runtime_measurements" \
			 " [--validate] [--verbose]" \
			 " [--verify [IMA public keys dir]]\n", argv[0]);
		return 1;
	}

	for (i = 2; i < argc; i++) {
		if (strncmp(argv[i], "--validate", 8) == 0)
			validate = 1;
		else if (strncmp(argv[i], "--verbose", 7) == 0)
			verbose = 1;
		else if (strncmp(argv[i], "--verify", 6) == 0)
			verify = 1;
		else
			keypath = argv[i];
	}

	if (verify) {
		if (pkey_init(keypath) < 0)
			printf("Verifying teplate hash only\n");
		else
			verify_sig = 1;
	}

	fp = fopen(argv[1], "r");
	if (!fp) {
		printf("fn: %s\n", argv[1]);
		perror("Unable to open file\n");
		return 1;
	}
	memset(pcr, 0, SHA256_DIGEST_LENGTH);	/* initial PCR content 0..0 */
	memset(zero, 0, SHA256_DIGEST_LENGTH);
	memset(fox, 0xff, SHA256_DIGEST_LENGTH);

	OpenSSL_add_all_digests();

	print_info( "### PCR HASH                                  " \
			"TEMPLATE-NAME\n");
	while (fread(&template.header, sizeof template.header, 1, fp)) {
		//SHA_CTX c;
		SHA256_CTX c;

		/* Extend simulated PCR with new template digest */
		/* SHA1_Init(&c);
		SHA1_Update(&c, pcr, SHA_DIGEST_LENGTH); */

		SHA256_Init(&c);
		SHA256_Update(&c, pcr, SHA256_DIGEST_LENGTH);
		if (validate) {
			if (memcmp(template.header.digest, zero, 20) == 0)
				memset(template.header.digest, 0xFF, 20);
		}
		/* SHA1_Update(&c, template.header.digest, 20);
		SHA1_Final(pcr, &c); */

		SHA256_Update(&c, template.header.digest, 20);
		SHA256_Final(pcr, &c);

		print_info("%3d %03u ", count++, template.header.pcr);
		display_digest(template.header.digest, SHA256_DIGEST_LENGTH);
		if (template.header.name_len > TCG_EVENT_NAME_LEN_MAX) {
			printf("%d ERROR: event name too long!\n",
				template.header.name_len);
			fclose(fp);
			EVP_cleanup();
			exit(1);
		}
		memset(template.name, 0, sizeof template.name);
		fread(template.name, template.header.name_len, 1, fp);
		print_info(" %s ", template.name);

		if (read_template_data(&template, fp) < 0) {
			tst_resm(TFAIL, "Reading of measurement entry failed");
			break;
		}

		if (parse_template_data(&template) != 0)
			print_info(" %s ", template.name);
			tst_resm(TFAIL, "Parsing of measurement entry failed");

		if (verify) {
			if (verify_template_hash(&template) != 0)
				hash_failed++;
		}
		print_info("\n");
		free(template.template_data);
	}
	fclose(fp);
	EVP_cleanup();

	verbose = 1;
	print_info("PCRAggr (re-calculated):");
	display_pcr(pcr, SHA256_DIGEST_LENGTH);
	print_info("\n");

	if (verify)	
		tst_resm(!hash_failed ? TFAIL : TINFO,
			"Template hash verification failures: %d", hash_failed);

	if (verify_sig) {
		tst_resm(!no_sigs ? TFAIL : TINFO, "Missing signatures: %d",
			 no_sigs);
		tst_resm(!unknown_keys ? TFAIL : TINFO ,
			 "Missing public key: %d", unknown_keys);
		tst_resm(!invalid_sigs ? TFAIL : TINFO,
			 "Invalid signature: %d", invalid_sigs);
	}

#else
	tst_resm(TCONF, "System doesn't have openssl/sha.h");
#endif
	tst_exit();
}
