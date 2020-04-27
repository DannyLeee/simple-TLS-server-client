#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CA_CERT "ca.crt"

// right certificate
#define HOST_CERT "host.crt"
#define HOST_KEY "host.key"

// wrong certificate
// #define HOST_CERT "wrong.crt"
// #define HOST_KEY "wrong.key"

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}


// 初始化 openssl
void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

// 創建 SSL context
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLSv1_2_server_method();    // create 的方法

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

// 配置 SSL context
void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);  // 選擇橢圓曲線

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, HOST_CERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, HOST_KEY, SSL_FILETYPE_PEM) <= 0 ) {
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
        printf("Client certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);   // 把 STDOUT buffer 拿掉
    int sock;
    SSL_CTX *ctx;

    // 初始化 openssl
    // init_openssl();
    SSL_library_init();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(8787);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        char *reply;
        char receive[1024];
        int count;
        FILE *fp;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);    // 配對 SSL 跟新的連線 fd
        SSL_set_verify_depth(ssl, 1);


        // SSL_accept() 處理 TSL handshake
        if (SSL_accept(ssl) <= 0) {
            if (SSL_get_verify_result(ssl) != X509_V_OK)
            {
                fprintf(stderr, "Client certificate verify error\n");
                printf("Connection close\n");
                // exit(EXIT_FAILURE);
            }
            else
            {
                fprintf(stderr, "Other connection error\n");
                printf("Connection close\n");
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            exit(EXIT_FAILURE);
        }
        else {
            printf("get connect!!\n");
            printf("Verification success!!\n");
            ShowCerts(ssl);        /* get any certificates */

            // send to client
            // printf("Send some to client: ");
            // scanf("%s", reply);
            // SSL_write(ssl, reply, strlen(reply));   // 送出訊息

            count = SSL_read(ssl, receive, sizeof(receive));
            receive[count] = 0;
            printf("Received from client:\n");
            printf("%s\n\n", receive);

            if (strcmp(receive, "list_file") == 0)
            {
                reply = "choise a file to copy\n";
                SSL_write(ssl, reply, strlen(reply));   // 送出訊息
                if ((fp = popen("ls | cat", "r")) == NULL)
                {
                    perror("open failed!");
                    return -1;
                }
                char buf[256];
                while (fgets(buf, 255, fp) != NULL)
                {
                    // printf("%s", buf);
                    SSL_write(ssl, buf, strlen(buf));
                }
                printf("ls done\n");
                if (pclose(fp) == -1)
                {
                    perror("close failed!");
                    return -2;
                }              
            }
            else if (strncmp(receive, "copy_file", 9) == 0)
            {
                char *file_name = strtok(receive, " ");
                puts(file_name);
                file_name = strtok(NULL, " ");
                puts(file_name);

                if ((fp = fopen(file_name, "rb")) == NULL)
                {
                    perror("File opening failed");
                    // return -1;
                }
                int c; // note: int, not char, required to handle EOF
                printf("Copying file: %s ... ...\n", file_name);
                while ((c = fgetc(fp)) != EOF) { // standard C I/O file reading loop
                    SSL_write(ssl, c, sizeof(c));
                }
                printf("File copy complete");
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();/****/
}