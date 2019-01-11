/*
** server.c -- a stream socket server demo
//	Receiving
	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    }
//	Sending
	if (send(new_fd, "Hello, world!", 13, 0) == -1)
		perror("send");

*/

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "./dh.h"   // Implementation of Diffie - Hellman algorithm
#include "./aes.h" // Implementation of aes alogrithm
#include "./logger.h"
#include "./server_messages.h"

#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold

#define MAXDATASIZE 100
static void phex(uint8_t* str);

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

int read_decrypted(int socket, struct AES_ctx context, char output[MAXDATASIZE]){
    uint8_t plain_text[64] = {0x00};
    if (recv(socket, plain_text, sizeof(plain_text), 0) == -1)
        return 0;    
    for (int i = 0; i < 4; ++i)
    {
      AES_ECB_decrypt(&context, plain_text + (i * 16));
    }
    char buffer[64] = {'\0'};
    memcpy(buffer, plain_text, 64);
    memcpy(output, plain_text, 64);
    printf("Received : %s\n", buffer);
    if(strncmp("exit", buffer, 4) == 0){
        printf("Exiting \n");
        return -1;
    }
    return 1;
}


char *get_output_of_command(FILE* pipe, char output[64]){
    //char* output = (char*)calloc(64, sizeof(char));

    while(fgets(output, sizeof(char)*63, pipe)!= NULL){
        printf("out: %s\n", output);
        return output;
    }
    return NULL;
}

int transmit_encrypted(int socket, struct AES_ctx context, char msg[64]){
    printf("Transmit message : %s\n", msg);
    uint8_t plain_text[64] = {(uint8_t)0x00};
    memcpy(plain_text, msg, 64);
    
    for (int i = (uint8_t) 0; i < (uint8_t) 4; ++i)
    {
        AES_ECB_encrypt(&context, plain_text + (i * 16));
    }
    
    printf("encrpted and sent\n");

    if (send(socket, plain_text, 64*sizeof(uint8_t), 0) == -1){
        printf("Failure on send encrypted\n");
        return 0;
    }
    return 1;
}

int execute_command(int socket, struct AES_ctx context, char * comm){
    FILE* pipe;
    char output[64];
    pipe = popen(comm, "r");
    if(pipe == NULL){
        printf("Could not read user's available commands\n");
        return -1;
    }
    while(get_output_of_command(pipe, output) != NULL){
        transmit_encrypted(socket, context, output);
    }
    strncpy(output, "EOFEOFEOF", 9);
    transmit_encrypted(socket, context, output);
    pclose(pipe);
    return 1;
}
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

uint64_t init_dh_key_exchange(int socket, uint64_t *key_param){
    uint64_t a = randomint64();
    uint64_t A = powmodp(G, a); //<-- send to client
    *key_param = rand();
    uint64_t opc[3] = {DH_KEY_TRANS, A, *key_param};
    printf("Key exhange initiated...");
    if (send(socket, opc, sizeof(opc), 0) == -1)
        return 0;
    if (recv(socket, opc, sizeof(opc), 0) == -1)
        return 0;
    printf("Response received.\n");
    uint64_t secret1 = powmodp(opc[1],a);
    return secret1;
}

int send_command_status(int socket, int opcode){
    int k = rand();
    int opc[2] = {opcode, k};
    if (send(socket, opc, sizeof(opc), 0) == -1)
        return 0;
    return k;
}

int get_seed(){
    return rand();
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

int perform_authentication(int socket){
    printf("Authenticating:");
    int salt;
    if((salt = send_command_status(socket, CREDENTIALS_REQUEST)) <= 0)
        printf("Error : sOPCODE");
    printf("Testing user against : %d\n", salt);
    int status = 0;
    char buf_L[MAXDATASIZE * 2 + 1] = {'\0'};
    //  LOGIN
    if (recv(socket, buf_L, MAXDATASIZE-1, 0) == -1)
        return -1;
    //  PASSWORD

    printf("Received data: %s\n", buf_L);
    status = 1;
    //  Check credentials credibility - the crude and simple text file version 
    //  You can insert Your own code here
    /*
    char username[MAXDATASIZE];
    char passhash[MAXDATASIZE];
    FILE* database = fopen("./users", "r");
    while(!feof(database)){
        fscanf(database, "%s:%s\n", username, passhash);
        //  FOUND USER IN DATABASE - CHECK HIS PASSWORD
        if(strcmp(username, buf_L)){
            if(strcmp(passhash, buf_P)){
                printf("It's a match\n"); // - User can be logged in
                status = 1 <- log user in
            }
        }
    }
    fclose(database);
    */
    return status;
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

int main(void){

    srand(time(NULL));
   
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");
    char buf[MAXDATASIZE];
    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener
            /*if (send(new_fd, "Hello, world!", 13, 0) == -1)
                printf("Error on : send");*/ //     <-- DESYNC on MOTD
            if(perform_authentication(new_fd) <= 0)
                printf("Error on : AUTH");
            int s_secret=0;
            uint64_t iv;
            if((s_secret = init_dh_key_exchange(new_fd, &iv)) == 0)
                printf("Error on : AUTH");
            //  Init encrypted transmission:
            struct AES_ctx ctx = init_encryption(new_fd, iv);
            if(transmit_encrypted(new_fd, ctx, PROMPT) <= 0)
                printf("Error on : encrtransmit\n");
            while(1){
                char command_buffer[MAXDATASIZE] = {'\0'};
                    int stat = read_decrypted(new_fd, ctx, command_buffer);
                    //printf("Comm buf: %s\n", command_buffer);
                    if(stat  < 0){
                        printf("Client logged out.\n");
                        close(new_fd);
                        exit(0);
                    }
                    execute_command(new_fd, ctx, command_buffer);
            }
            close(new_fd);
            exit(0);
        }
        close(new_fd);  // parent doesn't need this
    }

    return 0;
}