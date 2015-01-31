#include <stdio.h>
#include <gcrypt.h>
#include <stdlib.h>


#define RSA_MAX_BLOCK_LENGTH 16   // Block Length for RSA Encryption

/* Mode of Operation for RSA Key Generation, Encryption && Decryption*/
#define RSA_MODE_1024 1 
#define RSA_MODE_4096 2

/*  Function to Generate rsa Signature */
char* digitalSignature(char *, char *);

/* Function to generate Secure Expression */
char* extractString_secureExpression(gcry_sexp_t);

/* Function to generate Key pairs */
void generateRSAkey(char **, char **, int);

/* Function to perform RSA Encryption */
void rsaEncrypt(char*, char *, int);

/*Function to perform RSA Decryption */
void rsaDecrypt(char*, int);





