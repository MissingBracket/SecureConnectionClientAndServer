/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "./dh.h"
#include "./logger.h"
#include "./server_messages.h"
#include "aes.h"
#include "./high5.h" //-- For further functionalities
#define PORT "3490" // the port client will be connecting to 

 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int stringlen(char * string){
	int count = 0;
	char* it = string;
	while(*it && *it != '\0'){
		count++;
		it++;
	}
	return count;
}

// prints string as hex
static void phex(uint8_t* str)
{

#if defined(AES256)
    uint8_t len = 32;
#elif defined(AES192)
    uint8_t len = 24;
#elif defined(AES128)
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

int read_decrypted(int socket, struct AES_ctx context){
    uint8_t plain_text[64] = {0x00};
    if (recv(socket, plain_text, sizeof(plain_text), 0) == -1)
        return 0;
   
    //printf("Transmission received: \n");
    printf("\n");
    for (int i = 0; i < 4; ++i)
    {
      AES_ECB_decrypt(&context, plain_text + (i * 16));
    }
    char buffer[64] = {'\0'};
    memcpy(buffer, plain_text, 64);

    if(strncmp(buffer, "EOFEOFEOF", 9) == 0)
        return -1;
    printf("%s", buffer);
    

    return 1;
}


int transmit_encrypted(int socket, struct AES_ctx context, char msg[64]){
    printf("Transmit message : %s\n", msg);
    uint8_t plain_text[64] = {(uint8_t)0x00};
    memcpy(plain_text, msg, 64);
    
    for (int i = (uint8_t) 0; i < (uint8_t) 4; ++i)
    {
        AES_ECB_encrypt(&context, plain_text + (i * 16));
    }

    if (send(socket, plain_text, 64*sizeof(uint8_t), 0) == -1){
        printf("Failure on send encrypted\n");
        return 0;
    }
    return 1;
}

int str_equals_to(char* str1, char* str2){
	if(stringlen(str1) != stringlen(str2))
		return 0;
	char *it1 = NULL, *it2 = NULL;
	it1=str1;
	it2=str2;
	for(int i = 0; i < MAXDATASIZE; i++){
		if(*it1 != *it2)
			return 0;
	}
	return 1;
}

int send_command(int socket, char command[MAXDATASIZE]){
	if(stringlen(command) >= 100)
		return -1;

	int status = send(socket, command, stringlen(command), 0);
	//	Send command,
	//
	return status;
}

int receive_command_code(int socket, int *arg){
    int opc[2] = {0};
    if (recv(socket, opc, sizeof(opc), 0) == -1)
        return 0;
    *arg = opc[1];
    return opc[0];
}

uint64_t init_dh_key_exchange(int socket, uint64_t *key_param){
    uint64_t b = randomint64();
    uint64_t B = powmodp(G, b); //<-- send to server
    uint64_t A;
    uint64_t opc[3] = {DH_KEY_TRANS, 0};
    printf("Key exhange initiated...");
    if (recv(socket, opc, sizeof(opc), 0) == -1)
        return 0;
    A = opc[1];
    opc[1] = B;
    *key_param = opc[2];
    if (send(socket, opc, sizeof(opc), 0) == -1)
        return 0;
    printf("Response sent.\n");

    uint64_t secret2 = powmodp(A,b);
    //printf("a=%I64x s=%I64x\n", b,secret2);
    return secret2;
}

struct AES_ctx init_encryption(uint64_t iv, uint64_t key){
    uint64_t iv_temp[] = {iv, G};
    uint64_t key_temp[] = {key, G};
    uint8_t iv_arr[16] = {0};
    uint8_t key_arr[16] = {0};
    memcpy(iv_arr, iv_temp, 16); // <-- now there is an array for init
    memcpy(key_arr, key_temp, 16);
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key_arr, iv_arr);
    return ctx;
}

int perform_authentication_from_args(int socket, char* login, char *pass){

}

int perform_authentication(int socket, int salt){
    printf("Authenticating\n");
    char buf_L[MAXDATASIZE]={'\0'};
    char buf_P[MAXDATASIZE]={'\0'};
    printf("Received salt: %d\n", salt);
    char loginpacket[2*MAXDATASIZE + 1] = {'\0'};
    printf("USERNAME%s", PROMPT);
    scanf("%s", buf_L);
    printf("PASSWORD%s", PROMPT);
    scanf("%s", buf_P);
    printf("Request sent...");
    char hashbuffer[64];
    sprintf(hashbuffer, "%s:%d", buf_P, salt);
    char sha256Digest[65];
    hashToSHA256(hashbuffer, sha256Digest);

    sprintf(loginpacket, "%s:%s", buf_L, sha256Digest);
    send_command(socket, loginpacket);
}

int main(int argc, char *argv[])
{
    int sockfd, numbytes;  
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc != 2) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    int st=0;
    int arg=0;
    if((st=receive_command_code(sockfd, &arg)) <= 0){
     perror("recv");
        exit(1);   
    }
    uint64_t iv;
    printf("command status: %d\n", st);
    perform_authentication(sockfd, arg);
    init_dh_key_exchange(sockfd, &iv);
    struct AES_ctx ctx = init_encryption(sockfd, iv);
    if(read_decrypted(sockfd, ctx) <= 0)
        printf("Message read failed\n");
    char buffer[45] = {'\0'};
    char *line = NULL;
    size_t len;
    while(1){
        printf(":>_");
        getline(&line, &len ,stdin);
        transmit_encrypted(sockfd, ctx, line);
            char commparse[4] = {'\0'};
            strncpy(commparse, line, 4);
        if(strncmp("exit", commparse, 4) == 0){
            printf("Exiting\n");
            close(sockfd);
            exit(0);
        }
        while(read_decrypted(sockfd, ctx) > 0){

        }

    }
    buf[numbytes] = '\0';

    close(sockfd);

    return 0;
}