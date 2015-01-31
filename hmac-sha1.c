#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <sys/stat.h>
#include "hmac.h"

#define KEY_LENGTH_HMAC_SHA1 16

char* computehmacSHA1(char *fileName)
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
	
	stat(fileName , &st);
	int fileSize = st.st_size;
	key = randomkeyGenerate(KEY_LENGTH_HMAC_SHA1);
	error = gcry_md_open(&handle,GCRY_MD_SHA1, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
	if(error)
	{
			printf(" The Error : gcry_md_open computehmacSHA1 %s \n", gcry_strerror(error));
			return;
	}
	error = gcry_md_enable (handle, GCRY_MD_SHA1);
	if(error)
	{
			printf(" The Error : gcry_md_enable computehmacSHA1 %s \n", gcry_strerror(error));
			return;
	}
	error = gcry_md_setkey (handle, key, strlen(key));
	if(error)
	{
			printf(" The Error : gcry_md_setkey computehmacSHA1 %s \n", gcry_strerror(error));
			return;
	}
	fileContent = (char*) malloc(sizeof(char)*(fileSize));
	fin = fopen(fileName, "r");

	int bytes = fread(fileContent, sizeof(char), fileSize, fin);
	hashSize = gcry_md_get_algo_dlen(GCRY_MD_SHA1);

	gcry_md_write (handle, fileContent, fileSize-1);
	gcry_md_final (handle);
	msgDigest = gcry_md_read(handle, GCRY_MD_SHA1);
	
	printf(" The message Digest :");
	for (index = 0; index<hashSize; index++)
        printf("%02X", (unsigned char)msgDigest[index]); 
    printf("\n");
    gcry_md_close(handle);
    fclose(fin);
    free(fileContent);
    resetVariable(2, fileContent, key);
}
