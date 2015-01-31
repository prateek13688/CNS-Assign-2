#include <stdio.h>
#include <gcrypt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include "aes.h"


void aes256Encrypt(gcry_cipher_hd_t handle, char* plainText, char* encBuffer, FILE* fin, FILE* fout, int blockLength)
{
	int bufSize = blockLength; 
	int bytes, index;
	char padByte;
	while(!feof(fin))
    {
		memset(plainText, 0, bufSize);
        memset(encBuffer, 0, bufSize);
        bytes = fread(plainText, sizeof(char), bufSize, fin);
        if (!bytes) break;
        if(bytes < bufSize)
        {
			padByte = (char) (bufSize - bytes);
			while(bytes < bufSize)
				plainText[bytes++] = padByte;
		}
        gcry_cipher_encrypt(handle, encBuffer, bufSize, plainText, bufSize);
        bytes = fwrite(encBuffer, sizeof(char), bufSize, fout);
    }
}

void aes256Decrypt(gcry_cipher_hd_t handle, char* decrypttext, char* encBuffer, int blockLength, FILE* fin, FILE* fout)
{	
		struct stat st;
		int totalbytesRead = 0;
		int bytesRead, byteWrite, j;
		int bufSize = blockLength;
		stat("out" , &st);
		int encryptfileSize = st.st_size;
		while(!feof(fin))
		{	memset(decrypttext, 0, bufSize);
			memset(encBuffer, 0, bufSize);
			bytesRead = fread(encBuffer, 1, bufSize, fin);
			if (!bytesRead) break;
			gcry_cipher_decrypt(handle, decrypttext, bufSize, encBuffer,bufSize);
			if(totalbytesRead >= (encryptfileSize - blockLength))
				handlePadding(decrypttext, fout, blockLength, bytesRead);
			else
				byteWrite = fwrite(decrypttext, 1, bufSize, fout);
        totalbytesRead +=  bytesRead;
		}
}

void aes256Algorithm(char *fileName, double *encryptionTime, double *decryptionTime, int index)
{
	char initVector[16];
    char *encBuffer = NULL;
    char *plaintext = NULL;
    char *decrypttext = NULL;
    clock_t start_time, end_time;
    struct stat st;
    FILE *fp, *fpout;
    char *key = NULL;
    gcry_cipher_hd_t hd;
    int keyLength = 0, blockLength = 0;
    int     bufSize = 16, bytes ;
    int totalbytesRead = 0;
    char padByte;
    double performTime, cpuCycle = CLOCKS_PER_SEC;
    memset(initVector, 0, 16);
    
	keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	blockLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	
    plaintext = malloc(blockLength);
    encBuffer = malloc(blockLength);
    decrypttext = malloc(blockLength);
    
    fp = fopen(fileName, "r");
    fpout = fopen("aes256EncyptFile", "w");
    
    key = randomkeyGenerate(keyLength);
    printf(" The Random Key %s \n", key);
    
    gcry_cipher_open(&hd, GCRY_CIPHER_AES256 , GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd, key, keyLength);
    gcry_cipher_setiv(hd, initVector, blockLength);

	start_time = clock();
    aes256Encrypt(hd, plaintext, encBuffer, fp, fpout, blockLength);
    end_time = clock();
    performTime = ((end_time - start_time)/cpuCycle);
    encryptionTime[index] = performTime;
    
    gcry_cipher_close(hd);
    fclose(fp);
    fclose(fpout);

    /* Decryption of file aes256EncyptFile */
    fp = fopen("aes256EncyptFile", "r");
	fpout = fopen("aes256DecryptFile", "w");
    gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd, key, keyLength);
    gcry_cipher_setiv(hd, initVector, blockLength);
    
    start_time = clock();
    aes256Decrypt(hd, decrypttext, encBuffer, blockLength, fp, fpout);
    end_time = clock();
    performTime = ((end_time - start_time)/cpuCycle);
    decryptionTime[index] = performTime;
    
    gcry_cipher_close(hd);
    	
    free(plaintext);
    free(encBuffer); 
    free(decrypttext);
    
    fclose(fp);
    fclose(fpout);
    
    encBuffer = NULL;
    decrypttext = NULL;
    plaintext = NULL;
}

