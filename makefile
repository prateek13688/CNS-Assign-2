#
# Makefile for Encryption && Decryption
# Author: Prateek Jain
# 
# run make clean to clean
# run make to generate compile
COMPILER=gcc
CFLAGS=-w
LIB=-lgcrypt
cryptogator:
	$(COMPILER) $(CLAGS) -w cryptogator.c -o cryptogator aes128.c aes256.c hmac-sha1.c hmac-MD5.c hmac-sha256.c digitalSignature.c performance.c rsa.c -lgcrypt
clean:
	rm -rf *.o cryptogator rsa1024DecryptFile rsa1024EncryptFile rsa4096DecryptFile rsa4096EncryptFile AES128EncryptOutput AES128DecryptOutput aes256EncyptFile aes256DecryptFile
