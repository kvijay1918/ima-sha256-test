#define print_info(format, arg...) \
	if (verbose) \
		printf(format, ##arg)

#define log_err(format, arg...) \
		printf(format, ##arg)

static int display_pcr(u_int8_t * digest, u_int32_t digestlen)
{
	int i;

	for (i = 0; i < digestlen; i++)
		print_info("%02X ", (*(digest + i) & 0xff));
	return 0;
}

static inline void hexdump(unsigned char *buffer, unsigned int buffer_len)
{
	unsigned int i;

	for (i = 0; i < buffer_len; i++)
		printf("%02x", (*(buffer + i) & 0xff));
}

static inline void get_keyid_name(char *name, char *buf)
{
	sprintf(name, "%02x%02x%02x%02x", (*buf &0xff),
		 (*(buf + 1) & 0xff), (*(buf+2) & 0xff), (*(buf+3) & 0xff));
}

