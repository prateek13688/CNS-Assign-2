#include <stdio.h>
#include <gcrypt.h>
#include <sys/stat.h>

char* randomkeyGenerate(int);
void resetVariable(int , ...);

/* Function to computer HMAC-MD5 */
char* computehmacMD5(char *);  

/* Function to computer HMAC-SHA256 */
char* computehmacSHA256(char *);

/* Function to computer HMAC-SHA1 */
char* computehmacSHA1(char *);
