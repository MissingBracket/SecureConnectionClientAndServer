#include "./high5.h"
#include <string.h>
char* get_hash(char input[MD5_DIGEST_LENGTH]){
	char* ptr = NULL;
	int len = 0;
	ptr = input;
	while(*ptr || *ptr != '\0'){
		len++;
		ptr++;
	}
	unsigned char c[MD5_DIGEST_LENGTH] = {'\0'};
//	unsigned char *c = calloc(MD5_DIGEST_LENGTH, sizeof(unsigned char));
	char *toreturn = calloc(64, sizeof(char));
	
	MD5_CTX mdContext;
	int bytes;
	MD5_Init(&mdContext);
	MD5_Update(&mdContext, input, len);
	MD5_Final(c, &mdContext);
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
		printf("%.02x", c[i]);
	}
	sprintf(toreturn, "%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x%.02x",
		c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7],c[8],c[9],c[10],c[11],c[12],c[13],c[14],c[15]);
	printf("\n");
	return toreturn;
}

void hashToSHA256(char * string, char outputBuffer[65]){
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen(string));
	SHA256_Final(hash, &sha256);
	for(int i =0; i < SHA256_DIGEST_LENGTH ;i++){
		sprintf(outputBuffer + (i*2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
}