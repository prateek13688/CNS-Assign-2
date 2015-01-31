#include <stdio.h>
#include <gcrypt.h>
#include "rsa.h"


char* digitalSignature(char *privateKey, char *document)
{ 
	gcry_error_t error;
	gcry_mpi_t fileData;
	char *signature;
	int bytes;
	if ((error = gcry_mpi_scan(&fileData, GCRYMPI_FMT_USG, document, strlen(document), NULL))) 
	{
		printf("Error in gcry_mpi_scan() Rsa Sign%s\n", gcry_strerror(error));
		return;
	}
	gcry_sexp_t data;
	size_t erroff;
	if ((error = gcry_sexp_build(&data, &erroff, "(data (flags raw) (value %m))", fileData))) 
	{
		printf("Error in building security Expression %s \n",gcry_strsource(error));
		return;	
	}
	gcry_sexp_t privatekeySExp = generateSExpress(privateKey);
	gcry_sexp_t rsaSign;
	if ((error = gcry_pk_sign(&rsaSign, data, privatekeySExp))) 
	{
		printf("Error in gcry_pk_sign(): %s\n", gcry_strerror(error));
		return;
	}
	printf(" The Document Signed!!!! \n");
	signature = extractString_secureExpression(rsaSign);
	printf(" The Signature Generated %s \n",signature);
	
	return signature;
}
