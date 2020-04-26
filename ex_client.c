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
#define CA_CERT "ca.crt"

// right certificate
#define CLIENT_CERT "client.crt"
#define CLIENT_KEY "client.key"

// wrong certificate
// #define CLIENT_CERT "wrong.crt"
// #define CLIENT_KEY "wrong.key"

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

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
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
void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);  // 選擇橢圓曲線

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0 ) {
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
    char buf[1024];
    int bytes;
    char *hostname, *port;

    if ( argc != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", argv[0]);
        exit(0);
    }
    SSL_library_init();
    hostname = argv[1];
    port = argv[2];

    while (1)
    {
        ctx = InitCTX();
        configure_context(ctx);
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
            printf("Verification success!!\n");
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);        /* get any certificates */

            // long t = test(ctx, ssl);
            // printf("t = %d\n", t);
            // if (verify(ssl) != 1)
            //     return -1;

            // read from STDIN and send to server
            printf("Send some to server: ");
            scanf("%s", msg);
            SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
            
            // read from server and print to STDOUT
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
            buf[bytes] = 0;
            printf("Received from server:\n");
            printf("%s\n\n", buf);
            
            SSL_free(ssl);        /* release connection state */
        }
        close(server);         /* close socket */
        SSL_CTX_free(ctx);        /* release context */
    }
    return 0;
}