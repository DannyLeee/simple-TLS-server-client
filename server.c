#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "initial.h"

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
	    perror("Unable to create socket");
	    exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);   // 把 STDOUT buffer 拿掉
    int sock;
    SSL_CTX *ctx;

    char * _CERT;
    char * _KEY;
    switch (argc)
    {
    case 1:
        _CERT = HOST_CERT;
        _KEY =  HOST_KEY;
        break;
    case 2:
        _CERT = (strcmp(argv[1], "wrong") == 0) ? WRONG_CERT : HOST_CERT;
        _KEY = (strcmp(argv[1], "wrong") == 0) ? WRONG_KEY : HOST_KEY;
        break;
    default:
        fprintf(stderr, "wrong argument number\n");
        exit(EXIT_FAILURE);
        break;
    }

    // 初始化 openssl
    SSL_library_init();
    ctx = create_context(0);
    configure_context(ctx, _CERT, _KEY);
    sock = create_socket(8787);

    /* Handle connections */
    while(1) 
    {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        char *reply;
        char receive[1024];
        int count;
        FILE *fp;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0)
        {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);    // 配對 SSL 跟新的連線 fd
        SSL_set_verify_depth(ssl, 1);


        // SSL_accept() 處理 TSL handshake
        if (SSL_accept(ssl) <= 0)
        {
            if (SSL_get_verify_result(ssl) != X509_V_OK)
            {
                printf("Client certificate verify error\n");
                printf("Connection close\n");
            }
            else
            {
                printf("Other connection error\n");
                printf("Connection close\n");
            }
        }
        else
        {
            printf("get connect!!\n");
            printf("Verification client success!!\n");
            ShowCerts(ssl, 0);        /* get any certificates */

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
                file_name = strtok(NULL, " ");

                if ((fp = fopen(file_name, "rb")) == NULL)
                {
                    perror("File opening failed");
                    return -1;
                }
                printf("Copying file: %s ... ...\n", file_name);
                char r[64] = "Copying_file ";
                strcat(r, file_name);
                SSL_write(ssl, r, strlen(r));   // write state to client
                fseek(fp, 0, SEEK_END);
                int file_size = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                unsigned char *c = malloc(file_size * sizeof(char));
                fread(c, file_size, 1, fp);
                SSL_write(ssl, c, file_size);   // write whole file to client
                printf("File copy complete\n");
                fclose(fp);
                free(c);
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}