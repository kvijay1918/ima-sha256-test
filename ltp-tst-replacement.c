#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

int tst_res(int ttype, const char *fname, const char *arg_fmt, ...)
{
	va_list argp;
	int cnt;
	va_start(argp, arg_fmt);
	cnt = vprintf(arg_fmt, argp);
	printf("\n");
	va_end(argp);
	return(cnt);
}

int tst_resm(int ttype, const char *arg_fmt, ...)
{
	va_list argp;
	int cnt;
	va_start(argp, arg_fmt);
	cnt = vprintf(arg_fmt, argp);
	printf("\n");
	va_end(argp);
	return(cnt);
}

int tst_exit()
{
}
