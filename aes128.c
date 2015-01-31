#include <stdio.h>
#include <gcrypt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include "aes.h"

int handlePadding(char  *decrypttext, FILE* fout, int blockLength, int bytesRead)
{
	char *tempBuffer;
	int bytesWritten;
	int lastCharRead =  (int) decrypttext[bytesRead-1];
	if(lastCharRead > blockLength - 1  || (lastCharRead == 10))
		bytesWritten = fwrite(decrypttext, 1, 16, fout);
	else
	{
		int tempLength = blockLength - lastCharRead +1;
		tempBuffer = (char *) malloc(1 * tempLength);
		memset(tempBuffer , 0x0 , tempLength);
		strncpy(tempBuffer, decrypttext, blockLength - lastCharRead -1);
		bytesWritten = fwrite(tempBuffer, 1, strlen(tempBuffer), fout);
	}
	return bytesWritten;
}

void aes128Encrypt(gcry_cipher_hd_t handle, char* plainText, char* encBuffer, FILE* fin, FILE* fout)
{
	int bufSize = 16; 
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

void aes128Decrypt(gcry_cipher_hd_t handle, char* decrypttext, char* encBuffer, int blockLength, FILE* fin, FILE* fout)
{	
		struct stat st;
		int totalbytesRead = 0;
		int bytes , j;
		int bufSize = 16;
		stat("AES128EncryptOutput", &st);
		int encryptfileSize = st.st_size;
		while(!feof(fin))
		{	memset(decrypttext, 0, bufSize);
			memset(encBuffer, 0, bufSize);
			bytes = fread(encBuffer, 1, bufSize, fin);
			if (!bytes) break;
			gcry_cipher_decrypt(handle, decrypttext, bufSize, encBuffer,bufSize);
			if(totalbytesRead >= (encryptfileSize - blockLength))
				handlePadding(decrypttext, fout, blockLength, bytes);
			else
				bytes = fwrite(decrypttext, 1, bufSize, fout);
        totalbytesRead +=  bytes;
		}
}
void aes128Algorithm(char *fileName, double *encryptionTime, double *decryptionTime, int index)
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
    double performTime = 0;
    int keyLength = 0, blockLength = 0;
    int     bufSize = 16, bytes ;
    int totalbytesRead = 0;
    char padByte; int i=0; 
    
    double cpuCycle = CLOCKS_PER_SEC; 
 
    memset(initVector, 0, 16);
    
	keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128);
	blockLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128);
	
    plaintext = malloc(blockLength);
    encBuffer = malloc(blockLength);
    decrypttext = malloc(blockLength);
    
    fp = fopen(fileName, "r");
    if(!fp)
    {
			printf(" The File %s could not be opened \n", fileName);
			return;
	}
    fpout = fopen("AES128EncryptOutput", "w");
    
    key = (char*)randomkeyGenerate(keyLength);
    printf(" The Random Key %s \n", key);
    
    gcry_cipher_open(&hd, GCRY_CIPHER_AES128 , GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd, key, keyLength);
    gcry_cipher_setiv(hd, initVector, blockLength);
    
	start_time = clock();
    aes128Encrypt(hd, plaintext, encBuffer, fp, fpout);
    end_time = clock();
    performTime = ((end_time - start_time)/cpuCycle);
    encryptionTime[index] = performTime;
    
    
    gcry_cipher_close(hd);
    fclose(fp);
    fclose(fpout);

    /* Decrytping the AES128EncryptOutput */
    
    fp = fopen("AES128EncryptOutput", "r");
	fpout = fopen("AES128DecryptOutput", "w");
    gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd, key, keyLength);
    gcry_cipher_setiv(hd, initVector, blockLength);
    
    start_time = clock();
    aes128Decrypt(hd, decrypttext, encBuffer, blockLength, fp, fpout);
    end_time = clock();
    performTime = ((end_time - start_time) / cpuCycle);
    decryptionTime[index] = performTime;
    
    gcry_cipher_close(hd);
	fclose(fp);
	fclose(fpout);
	
    free(plaintext);
    free(encBuffer); 
    free(decrypttext);
    
    encBuffer = NULL;
    decrypttext = NULL;
    plaintext = NULL;
}
