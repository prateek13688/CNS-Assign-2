#include <stdio.h>
#include <gcrypt.h>
#include <stdlib.h>
#include "hmac.h"
#include "aes.h"
#include "rsa.h"
#include <time.h>
#include "performance.h"

#define MAX_OPERATION 100

void resetVariable(int num, ...)
{
	int i=0;
	va_list param;
	va_start(param , num);
	for(i = 0; i<num; i++)
	{
		char *p = va_arg(param , char*);
		p = NULL;
	}
}

void gcrypt_init()
{
// Version check makes sure that important subsystems are initalized
if (!gcry_check_version(GCRYPT_VERSION)) {
printf("libgcrypt version mismatch\n");
exit(2);
}
gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

char* randomkeyGenerate(int keyLength)
{
     static char characterSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!@#$^&"; 
     char *randomKey = NULL;
     int j = 0, keyIndex = 0;
     if(keyLength != 0)
     {
        randomKey = (char*) malloc(sizeof(char) * (keyLength+1));
        if(randomKey != NULL)
        {
	   for(j = 0; j < keyLength; j++)
	   {
             keyIndex = rand() % (strlen(characterSet)-1);
             randomKey[j] = characterSet[keyIndex];
           }
           randomKey[keyLength] = '\0';
        }
	else
          printf(" The Random Key = NULL ");
     }
     return randomKey;
}

int main(int argc, char *argv[])
{
	char *hashValue;
	char *fileName = argv[1];
	char *publicKey = NULL, *privateKey=NULL;
	char *digitalSign;
	double meanValue = 0, medianValue = 0;
	
	clock_t startTime , endTime;
	double performTime;
	double encryptionTime[MAX_OPERATION] = {0};
	double decryptionTime[MAX_OPERATION] = {0};
	
    double hashTime[MAX_OPERATION] = {0};
    
	double cpuCycle = CLOCKS_PER_SEC;
	
	int i=0;
	if(!fileName)
	{
			printf(" There is no file Name Given as Input \n");
			return;
	}
	gcrypt_init();
	printf("\n------------------ Performace of AES 128 Encryption && Decryption------------------------\n");
		
	for(i=0; i<MAX_OPERATION; i++)
		aes128Algorithm(fileName, encryptionTime, decryptionTime, i);

	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Encryption Time AES128: %d :  %lf \n", i , encryptionTime[i]);
		
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Decryption Time AES128: %d :  %lf \n", i , decryptionTime[i]);
		
	meanValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The mean time of AES128 Encryption %f \n", meanValue);
	
	medianValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The median time of AES128 Encryption %f \n", medianValue);
	
	meanValue = medianCalculate(decryptionTime, MAX_OPERATION);
	printf(" The mean time of AES128 Decryption %f \n", meanValue);
	
	medianValue = medianCalculate(decryptionTime, MAX_OPERATION);
	printf(" The median time of AES128 Decryption %f \n", medianValue);
	
	memset(encryptionTime, 0x0, MAX_OPERATION);
	memset(decryptionTime, 0x0, MAX_OPERATION);

	printf("\n------------------ Performace of AES 256 Encryption ------------------------\n");
	for(i = 0; i<MAX_OPERATION; i++)
		aes256Algorithm(fileName,encryptionTime, decryptionTime, i);
		
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Encryption Time AES256: %d :  %lf \n", i , encryptionTime[i]);
		
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Decryption Time AES256: %d :  %lf \n", i , decryptionTime[i]);
		
	meanValue = medianCalculate(encryptionTime, 2);
	printf(" The mean time of AES256 Encryption %f \n", meanValue);
	
	medianValue = medianCalculate(encryptionTime, 2);
	printf(" The median time of AES256 Encryption %f \n", medianValue);
	
	meanValue = medianCalculate(decryptionTime, 2);
	printf(" The mean time of AES256 Decryption %f \n", meanValue);
	
	medianValue = medianCalculate(decryptionTime, 2);
	printf(" The median time of AES256 Decryption %f \n", medianValue);
	
	memset(encryptionTime, 0x0, MAX_OPERATION);
	memset(decryptionTime, 0x0, MAX_OPERATION);
	
	printf("\n------------------ Performace of HMAC SHA1 ------------------------\n");
	for(i = 0; i<MAX_OPERATION; i++)
	{
		startTime = clock();
		hashValue = computehmacSHA1(fileName);
		endTime = clock();
		performTime = ((endTime - startTime)/cpuCycle);
		hashTime[i] = performTime;
	}
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Hashing Time of HMAC-SHA1: %d :  %lf \n", i , hashTime[i]);
	
	meanValue = medianCalculate(hashTime, MAX_OPERATION);
	printf(" The mean time of HMAC-SHA1 Hashing:  %f \n", meanValue);
	
	medianValue = medianCalculate(hashTime, MAX_OPERATION);
	printf(" The median time of HMAC-SHA1 Hashing %f \n", medianValue);
	
	memset(hashTime, 0x0, MAX_OPERATION);
	
		printf("\n------------------ Performace of HMAC MD5 ------------------------\n");
	for(i = 0; i<MAX_OPERATION; i++)
	{
		startTime = clock();
		hashValue = computehmacMD5(fileName);
		endTime = clock();
		performTime = ((endTime - startTime)/cpuCycle);
		encryptionTime[i] = performTime;
	}
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Hashing Time of HMAC MD5: %d :  %lf \n", i , encryptionTime[i]);
	
	meanValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The mean time of HMAC MD5 Hashing:  %f \n", meanValue);
	
	medianValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The median time of HMAC MD5 Hashing %f \n", medianValue);
	
	memset(encryptionTime, 0x0, MAX_OPERATION);
	memset(decryptionTime, 0x0, MAX_OPERATION);
	
		printf("\n------------------ Performace of HMAC SHA256 ------------------------\n");
	for(i = 0; i<MAX_OPERATION; i++)
	{
		startTime = clock();
		hashValue = computehmacSHA256(fileName);
		endTime = clock();
		performTime = ((endTime - startTime)/cpuCycle);
		encryptionTime[i] = performTime;
	}
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Hashing Time of HMAC SHA256: %d :  %lf \n", i , encryptionTime[i]);
	
	meanValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The mean time of HMAC SHA256 Hashing:  %f \n", meanValue);
	
	medianValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The median time of HMAC SHA256 Hashing %f \n", medianValue);
	
	memset(encryptionTime, 0x0, MAX_OPERATION);
	memset(decryptionTime, 0x0, MAX_OPERATION);
	
	hashValue = NULL; 
	
	printf("\n------------------ Performace of RSA 1024 Encryption && Decryption ------------------------\n");
	
	
	for(i = 0; i<MAX_OPERATION; i++)
	{
		generateRSAkey(&publicKey, &privateKey, RSA_MODE_1024);
		startTime = clock();
		rsaEncrypt(publicKey, fileName, RSA_MODE_1024);
		endTime = clock();
		performTime = ((endTime - startTime)/cpuCycle);
		encryptionTime[i] = performTime;

		startTime = clock();
		rsaDecrypt(privateKey, RSA_MODE_1024);
		endTime = clock();
		performTime = ((endTime - startTime)/cpuCycle);
		decryptionTime[i] = performTime;
	}
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Encryption Time of RSA1024: %d :  %lf \n", i , encryptionTime[i]);
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Decryption Time RSA1024: %d :  %lf \n", i , decryptionTime[i]);
	
	meanValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The mean encryption time of RSA1024:  %f \n", meanValue);
	
	medianValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The median encryption time of RSA1024 %f \n", medianValue);


	meanValue = calculateMean(decryptionTime, 2);
	printf(" The mean decrytion time of RSA1024 %f \n", meanValue);
	
	medianValue = calculateMedian(decryptionTime, 2);
	printf(" The median decryption time of RSA1024 %f \n", medianValue);
	
	memset(encryptionTime, 0x0, MAX_OPERATION);
	memset(decryptionTime, 0x0, MAX_OPERATION); 

	printf("\n------------------ Performace of RSA 4096 Encryption && Decryption ------------------------\n");
	
	
	for(i = 0; i<MAX_OPERATION; i++)
	{
		generateRSAkey(&publicKey, &privateKey, RSA_MODE_4096);
		startTime = clock();
		rsaEncrypt(publicKey, fileName, RSA_MODE_4096);
		endTime = clock();
		performTime = ((endTime - startTime)/cpuCycle);
		encryptionTime[i] = performTime;

		startTime = clock();
		rsaDecrypt(privateKey, RSA_MODE_4096);
		endTime = clock();
		performTime = ((endTime - startTime)/cpuCycle);
		decryptionTime[i] = performTime;
	}
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Encryption Time of RSA4096: %d :  %lf \n", i , encryptionTime[i]);
		
	for(i=0; i<MAX_OPERATION; i++)
		printf(" The Decryption Time RSA4096: %d :  %lf \n", i , decryptionTime[i]);
	
	meanValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The mean encryption time of RSA4096:  %f \n", meanValue);
	
	medianValue = medianCalculate(encryptionTime, MAX_OPERATION);
	printf(" The median encryption time of RSA4096 %f \n", medianValue);


	meanValue = medianCalculate(decryptionTime, 2);
	printf(" The mean decrytion time of RSA4096 %f \n", meanValue);
	
	medianValue = medianCalculate(decryptionTime, 2);
	printf(" The median decryption time of RSA4096 %f \n", medianValue);
	
	memset(encryptionTime, 0x0, MAX_OPERATION);
	memset(decryptionTime, 0x0, MAX_OPERATION);
	printf("\n------------------ Digital Signature ------------------------\n");
	/*Using the previously Generated RSA4096 Key to generate digital signature */
	
	/*Generating Hash SHA256 of the file */
		hashValue = computehmacSHA256(fileName);
		startTime = clock();
		digitalSign = digitalSignature(privateKey, hashValue);
		endTime = clock();
		performTime = ((endTime - startTime)/cpuCycle);
		encryptionTime[i] = performTime;
	
		printf(" The Time to Sign the Message: %d :  %lf \n", i , encryptionTime[0]);
		
		
	return 0;
}
