#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include "initial.h"

int OpenConnection(const char *hostname, int port)
{   
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        // connect fail
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);   // 把 STDOUT buffer 拿掉
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char receive[1024];
    int bytes;
    char *hostname, *port;

    char * _CERT;
    char * _KEY;
    switch (argc)
    {
    case 3:
        _CERT = CLIENT_CERT;
        _KEY =  CLIENT_KEY;
        break;
    case 4:
        _CERT = (strcmp(argv[3], "wrong") == 0) ? WRONG_CERT : CLIENT_CERT;
        _KEY = (strcmp(argv[3], "wrong") == 0) ? WRONG_KEY : CLIENT_KEY;
        break;
    default:
        fprintf(stderr, "usage: %s <hostname> <portnum> [wrong]\n", argv[0]);
        exit(EXIT_FAILURE);
        break;
    }

    // 初始化 openssl
    SSL_library_init();
    hostname = argv[1];
    port = argv[2];

    while (1)
    {
        ctx = create_context(1);
        configure_context(ctx, _CERT, _KEY);
        server = OpenConnection(hostname, atoi(port));

        ssl = SSL_new(ctx);      /* create new SSL connection state */
        SSL_set_verify_depth(ssl, 1);
        SSL_set_fd(ssl, server);    /* attach the socket descriptor */
        if (SSL_connect(ssl) == -1)   /* perform the connection */
        {
            if (SSL_get_verify_result(ssl) != X509_V_OK)
            {
                fprintf(stderr, "Server certificate verify error\n");
                printf("Connection close\n");
                exit(EXIT_FAILURE);
            }
        }
        else
        {   
            char *msg;
            printf("Verification server success!!\n");
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl, 1);        /* get any certificates */

            // read from STDIN and send to server
            printf("Send some to server: ");
            gets(msg);                
            SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
            // read from server and print to STDOUT
            printf("Received from server:\n");
            while ((bytes = SSL_read(ssl, receive, sizeof(receive))) != 0) /* get reply & decrypt */
            {
                receive[bytes] = 0;
                if (strncmp(receive, "Copying_file", 12) == 0)
                {
                    char *file_name = strtok(receive, " ");
                    file_name = strtok(NULL, " ");
                    strcat(file_name, "_copy");

                    FILE *fp = fopen(file_name,"wb");
                    while ((bytes = SSL_read(ssl, receive, sizeof(receive))) != 0) /* get reply & decrypt */
                    {
                        receive[bytes] = 0;
                        fwrite(receive, strlen(receive), 1, fp);
                    }   
                    fclose(fp);
                }
                else
                {
                    printf("%s", receive);
                }
            }
            printf("\n");
            SSL_free(ssl);        /* release connection state */
        }
        close(server);         /* close socket */
        SSL_CTX_free(ctx);        /* release context */
    }
    return 0;
}