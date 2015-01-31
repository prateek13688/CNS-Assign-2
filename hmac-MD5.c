#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <sys/stat.h>
#include "hmac.h"

#define KEY_LENGTH_HMAC_MD5 16

char* computehmacMD5(char *inputfileName)
{
	char *fileContent;
	char *key = NULL;
	int hashSize = 0;
	int j = 0;

	char *msgDigest;
	gcry_md_hd_t handle = NULL;
	FILE *fin;
	struct stat st;
	int index = 0;
	gcry_error_t  error;
	stat(inputfileName , &st);
	int fileSize = st.st_size;
	key = randomkeyGenerate(KEY_LENGTH_HMAC_MD5);
	printf(" Return The Random Key %s \n", key);
	error = gcry_md_open(&handle,GCRY_MD_MD5, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
	if(error)
	{
			printf(" The Error : gcry_md_open computehmacMD5 %s \n", gcry_strerror(error));
			return;
	}
	error = gcry_md_enable (handle, GCRY_MD_MD5);
	if(error)
	{
			printf(" The Error : gcry_md_enable computehmacMD5 %s \n", gcry_strerror(error));
			return;
	}
	printf(" The Handle Enabled for Cipher \n");
	error = gcry_md_setkey (handle, key, strlen(key));
	if(error)
	{
			printf(" The Error : gcry_md_setkey computehmacMD5 %s \n", gcry_strerror(error));
			return;
	}
	
	fileContent = (char*) malloc(sizeof(char)*(fileSize));
	fin = fopen(inputfileName, "r");

	int bytes = fread(fileContent, sizeof(char), fileSize, fin);

	hashSize = gcry_md_get_algo_dlen(GCRY_MD_MD5);
	printf(" The Hash Length %d \n", hashSize);
	gcry_md_write (handle, fileContent, fileSize-1);
	gcry_md_final (handle);
	msgDigest = gcry_md_read(handle, GCRY_MD_MD5);
	printf(" The message Digest: ");
	for (index = 0; index<hashSize; index++)
        printf("%02X", (unsigned char)msgDigest[index]); 
    printf("\n");
    gcry_md_close(handle);
    
    fclose(fin);
    free(fileContent);
    resetVariable(2, fileContent, key);
    
}

