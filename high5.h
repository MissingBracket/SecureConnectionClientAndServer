#include <sys/types.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
char* get_hash(char input[MD5_DIGEST_LENGTH]);
void hashToSHA256(char * string, char outputBuffer[65]);