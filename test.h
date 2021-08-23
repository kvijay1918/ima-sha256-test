extern int verbose;

#define TPASS      0    /* Test passed flag */
#define TFAIL      1    /* Test failed flag */
#define TBROK      2    /* Test broken flag */
#define TWARN      4    /* Test warning flag */
#define TRETR      8    /* Test retire flag */
#define TINFO      16   /* Test information flag */
#define TCONF      32   /* Test not appropriate for configuration flag */

int tst_res(int ttype, const char *fname, const char *arg_fmt, ...);

int tst_resm(int ttype, const char *arg_fmt, ...);

int tst_exit();
