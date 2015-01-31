#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <gpg-error.h>
#include <sys/stat.h>
#include "rsa.h"

gcry_sexp_t cipherContent;

gcry_sexp_t generateSExpress(const char* expression)
{
	gcry_error_t error;
	gcry_sexp_t sExpression;
	size_t length = strlen(expression);
	if ((error = gcry_sexp_new(&sExpression, expression, length, 1))) 
	{
		printf("Error in Generating Secure Expression %s \n", gcry_strsource(error));
		return;
	}
return sExpression;
	
}
char* extractString_secureExpression(gcry_sexp_t secureExp)
{
	//Length of Buffer for Storing the Secure Expression in Advance Format
	int bufferLength = gcry_sexp_sprint(secureExp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
	
	char *expBuffer = (char*) malloc(sizeof(char) * bufferLength);
	if(!expBuffer)
		printf("The Buffer Could not be allocated with memory \n");
	if((gcry_sexp_sprint(secureExp, GCRYSEXP_FMT_ADVANCED, expBuffer, bufferLength)) == 0)
	{
		printf(" The Expression cannot be copied with the length \n");
		return;	
	}
	return expBuffer;
}

void rsaEncrypt(char* publicKey, char *fileName, int RSA_MODE)
{
	gcry_error_t error;
	gcry_mpi_t fileData;
	gcry_sexp_t buildData;
	gcry_sexp_t cipherContent;
	char *cipherText;
	size_t secureexp_builderrCode;
	FILE *fin, *fout;
	char *fileContent;
	size_t bitsscanned;
	int j;
	fin = fopen(fileName, "r");
	if(!fin)
	{
			printf(" Error Opening the file %s\n", fileName);
			return;
	}
	if(RSA_MODE == 1)
		fout = fopen("rsa1024EncryptFile", "w");
	else if(RSA_MODE == 2)
		fout = fopen("rsa4096EncryptFile", "w");
	else
	{
			printf(" The Mode Entered is not legal Mode for RSA Encryption");
			return;
	}
	if(!fout)
	{
			printf(" Error Opening the file for ENcryption \n");
			return;
	}
	
		
	char *plaintext;
	fileContent = (char *)calloc((RSA_MAX_BLOCK_LENGTH +1), sizeof(char));
	
	gcry_sexp_t public_key = generateSExpress(publicKey);
	
	while(!feof(fin))
	{
		int bytes = fread(fileContent, sizeof(char),RSA_MAX_BLOCK_LENGTH, fin);
		if(!bytes)
		   break;
		error = gcry_mpi_scan(&fileData, GCRYMPI_FMT_USG,fileContent,strlen((const char*) fileContent),&bitsscanned);
		if(error)
		{
			printf(" Error while Scanning plaintext data %s \n", gcry_strerror(error));	
			return;
		}
		if(error)
		{
			printf(" Error while building secure expression data with error code %s\n", gcry_strerror(error));
			return;
		}
		error = gcry_sexp_build(&buildData, &secureexp_builderrCode, "(data (flags raw) (value %m))", fileData);
		if(error)
		{
			printf(" Error while building data in rsaEncrypt %s\n", gcry_strerror(error));
		}
		error = error = gcry_pk_encrypt(&cipherContent, buildData, public_key);
		if(error)
		{
			printf(" Error while Encrypting %s \n", gcry_strerror(error));
			return;	
		}
		cipherText = extractString_secureExpression(cipherContent);
		bytes = fwrite(cipherText, sizeof(char), strlen(cipherText), fout);	
	}
		free(fileContent);
		fclose(fin);
		fclose(fout);
}

void rsaDecrypt(char* privateKey, int RSA_MODE)
{
	FILE *fin;
	FILE *fout;
	struct stat st;
	char *fileContent = NULL;
	unsigned char *plainText;
	size_t plaintextSize;
	char *tempBuffer;
	
	char *lineRead = NULL;
    size_t lineLength = 0;
    ssize_t read;
    int lineCount = 1;
	
	gcry_error_t error;
	gcry_sexp_t fileData;
	gcry_sexp_t buildData;
	gcry_sexp_t decryptData;
	
	gcry_sexp_t private_Key = generateSExpress(privateKey);
	
	if( RSA_MODE == 1)
	{
		fin = fopen("rsa1024EncryptFile", "r");
		if(!fin)
		  printf("The FileCould Not be opened\n");
		fout = fopen("rsa1024DecryptFile", "w");
		if(!fout)
		  printf("The FileCould Not be opened\n");
	}
	else
	{
		fin = fopen("rsa4096EncryptFile", "r");
		fout = fopen("rsa4096DecryptFile", "w");
	}

		int currSize = 0;
		while (!feof(fin))
		{
			read = getline(&lineRead, &lineLength, fin) ;
		   if(lineCount>5)
		   {
				error = gcry_sexp_new(&fileData, fileContent, strlen(fileContent), 1);
				if(error)
				{
					printf(" Error while generating secure expression from cipher text %s \n", gcry_strerror(error));
					return;
				}
				error = gcry_pk_decrypt(&decryptData, fileData, private_Key);
				if(error)
				{
					printf(" Error while enerating decrypting from cipher text %s \n", gcry_strerror(error));
					return;
				}
				gcry_mpi_t plainData = gcry_sexp_nth_mpi(decryptData, 0, GCRYMPI_FMT_USG);
	
				error = gcry_mpi_aprint(GCRYMPI_FMT_USG, &plainText, &plaintextSize, plainData);
				if(error)
				{
					printf(" Error while copying the decrypted data %s \n", gcry_strerror(error));
					return;
				}
				
				int bytes = fwrite(	plainText, sizeof(char), plaintextSize, fout);
				if(fileContent)
				{
					free(fileContent);
					fileContent = NULL;
				}
				currSize = 0;
				lineCount = 1;
			}
           fileContent = (char*) realloc(fileContent, (currSize + strlen(lineRead)+1));
           if(currSize == 0)
				memset(fileContent, 0x0, strlen(lineRead));
           strncat(fileContent, lineRead, strlen(lineRead));
           currSize+=read;
           lineCount++;
		}	
    fclose(fin);
    fclose(fout);

}

void generateRSAkey(char **publicKey, char **privateKey, int RSA_MODE) 
{
	gcry_error_t error;
	gcry_sexp_t rsa_key;
	gcry_sexp_t key_parameters;
	
	gcry_sexp_t exppublicKey;        //secure Expression for Public Key
	gcry_sexp_t expprivateKey;	
	char * exp;
	
	if(RSA_MODE == RSA_MODE_1024)
		exp = "(genkey (rsa (transient-key) (nbits 4:1024)))";
	else if(RSA_MODE == RSA_MODE_4096)
		exp = "(genkey (rsa (transient-key) (nbits 4:4096)))";   // Expression to generate securExpression Parameters
	else
	{
		printf(" Wrong RSA Mode Selected for Generating Key \n"); return;
	}
	
	error = gcry_sexp_new(&key_parameters, exp, strlen(exp), 1);
	if(error)
	{
		printf(" The error while initializinf parameters %s \n", gcry_strerror(error));
		return;
	}
		
	error = gcry_pk_genkey(&rsa_key, key_parameters);
	if(error)
	{
		printf(" The error while generating public && private key %s \n", gcry_strerror(error));
		return;
	}
			
	exppublicKey = gcry_sexp_nth(rsa_key, 1);
	expprivateKey = gcry_sexp_nth(rsa_key, 2);
	
	*publicKey = extractString_secureExpression(exppublicKey);
	*privateKey = extractString_secureExpression(expprivateKey);
	printf(" The private Key %s \n", *privateKey);
}
