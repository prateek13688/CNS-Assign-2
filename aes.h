#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>


/*unction to handle the pading in blocks */
int handlePadding(char *, FILE*, int, int);

/* Function to initialize parameters for AES256 Encryption && AES256 Decryption */
void aes256Algorithm(char *, double *, double *, int);

/* Function to perform AES 256 Encryption */
void aes256Encrypt(gcry_cipher_hd_t, char*, char*, FILE*, FILE*, int);

/* Function to perform AES 256 Decryption */
void aes256Decrypt(gcry_cipher_hd_t, char*, char*, int, FILE*, FILE*);

/* Function to initialize parameters for AES128 Encryption && AES128 Decryption */
void aes128Algorithm(char *fileName, double *, double *, int);

/* Function to perform AES128 Decryption */
void aes128Decrypt(gcry_cipher_hd_t, char*, char*, int, FILE*, FILE*);

/* Function to perform AES128 Encryption */
void aes128Encrypt(gcry_cipher_hd_t, char*, char*, FILE*, FILE*);


