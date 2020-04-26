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

long test(SSL_CTX* ctx, SSL* ssl)
{
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    long result = SSL_get_verify_result(ssl);
    // if (result == X509_V_OK)
    //     return 1;
    // else
    //     return -1;
    return result;
}

void test2(SSL* ssl)
{
    X509 *cert;
    cert = SSL_get_peer_certificate(ssl);
    if ( cert != NULL )
    {
        // X509_STORE_CTX * s_ctx = X509_STORE_CTX_new();
        // X509_STORE_CTX_set_chain
        // X509_STORE_CTX_trusted_stack
        // X509_STORE_CTX_set_cert(s_ctx, cert);
        // X509_verify_cert

        int status;
        X509_STORE_CTX *ctx;
        ctx = X509_STORE_CTX_new();
        X509_STORE *store = X509_STORE_new();

        X509_STORE_add_cert(store, cert);

        X509_STORE_CTX_init(ctx, store, cert, NULL);

        status = X509_verify_cert(ctx);
        if(status == 1)
            printf("Certificate verified ok\n");
        else
            printf("%s\n", X509_verify_cert_error_string(ctx->error));
    }
    else
        printf("Info: No server certificates configured.\n");
}

int verify(SSL* ssl)
{
    X509 *cert;
    cert = SSL_get_peer_certificate(ssl);
    int result = 0;

    X509_STORE* m_store = X509_STORE_new();
    X509_LOOKUP* m_lookup = X509_STORE_add_lookup(m_store,X509_LOOKUP_file());    
    X509_STORE_load_locations(m_store, CA_CERT, NULL);
    X509_STORE_set_default_paths(m_store);
    X509_LOOKUP_load_file(m_lookup,CA_CERT,X509_FILETYPE_PEM);

    X509_STORE_CTX *storeCtx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(storeCtx,m_store,cert,NULL);
    X509_STORE_CTX_set_flags(storeCtx, X509_V_FLAG_CB_ISSUER_CHECK);
    if (X509_verify_cert(storeCtx) == 1)
    {
        printf("Verification success!!\n");
        result = 1;
    }
    else
        printf("Verification error: %s\n",X509_verify_cert_error_string(storeCtx->error));
    
    X509_STORE_CTX_free(storeCtx);
    if(m_store != NULL)
    {
        X509_STORE_free(m_store);
        m_store = NULL;
    }
    return result;
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
        server = OpenConnection(hostname, atoi(port));
        ssl = SSL_new(ctx);      /* create new SSL connection state */
        SSL_set_fd(ssl, server);    /* attach the socket descriptor */
        if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
            ERR_print_errors_fp(stderr);
        else
        {   
            char *msg;
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);        /* get any certificates */

            // long t = test(ctx, ssl);
            // printf("t = %d\n", t);
            if (verify(ssl) != 1)
                return -1;

            // read from STDIN and send to server
            scanf("%s", msg);
            SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
            
            // read from server and print to STDOUT
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
            buf[bytes] = 0;
            printf("Received from server:\n");
            printf("\{ %s \}\n\n", buf);
            
            SSL_free(ssl);        /* release connection state */
        }
        close(server);         /* close socket */
        SSL_CTX_free(ctx);        /* release context */
    }
    return 0;
}