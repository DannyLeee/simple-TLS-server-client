//SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define FAIL    -1

// set the ca path here
#define CA_CERT "ca.crt"

// set the certificate path here
// right certificate
#define RIGHT_CERT "client.crt"
#define RIGHT_KEY "client.key"
// wrong certificate
#define WRONG_CERT "wrong.crt"
#define WRONG_KEY "wrong.key"

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

// create client SSL context
SSL_CTX* InitCTX(void)
{   
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

// 配置 SSL context
void configure_context(SSL_CTX *ctx, const char *cert, const char *key)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);  // 選擇橢圓曲線

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
	    exit(EXIT_FAILURE);
    }
    SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

void ShowCerts(SSL* ssl)
{   
    X509 *cert; // Certificate display and signing utility
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No server certificates configured.\n");
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
        _CERT = RIGHT_CERT;
        _KEY =  RIGHT_KEY;
        break;
    case 4:
        _CERT = (strcmp(argv[3], "wrong") == 0) ? WRONG_CERT : RIGHT_CERT;
        _KEY = (strcmp(argv[3], "wrong") == 0) ? WRONG_KEY : RIGHT_KEY;
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
        ctx = InitCTX();
        configure_context(ctx, _CERT, _KEY);
        server = OpenConnection(hostname, atoi(port));
        
        ssl = SSL_new(ctx);      /* create new SSL connection state */
        SSL_set_verify_depth(ssl, 1);
        SSL_set_fd(ssl, server);    /* attach the socket descriptor */
        if (SSL_connect(ssl) == FAIL)   /* perform the connection */
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
            ShowCerts(ssl);        /* get any certificates */

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