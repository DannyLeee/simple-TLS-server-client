#include "initial.h"

// 創建 SSL context
SSL_CTX *create_context(int mode)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (mode == 0)
        method = TLSv1_2_server_method();    // create 的方法
    else
        method = TLSv1_2_client_method();

    ctx = SSL_CTX_new(method);
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
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
    SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

void ShowCerts(SSL* ssl, int mode)
{   
    X509 *cert; // Certificate display and signing utility
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        if (mode == 0)
            printf("Client certificates:\n");
        else
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
    {
        if (mode == 0)
            printf("Info: No client certificates configured.\n");
        else
            printf("Info: No server certificates configured.\n");
    }
}