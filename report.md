<p style="text-align:right;">
姓名:李韋宗<br>
學號:B10615024<br>
日期:2020/4/29<br>
</p>

<h1 style="text-align:center;"> Netweork Security - HW1

## 建置環境與使⽤說明
* WSL(Ubuntu 16.04 LST)
* VS code

## 使用說明
* [README](https://github.com/DannyLeee/simple-TLS-server/blob/master/README.md)
* step0: 先在 `initial.h` 中設定 CA, server, client 的憑證及公鑰路徑
* step1: 在目錄中執行 `make`
* step2: 在目錄中執行 `./server`
* step3: 在目錄中執行 `./client 127.0.0.1 8787`
* **如果使用時亦常中斷，重開 ./client 即可** (我也不知道為啥會這樣)

### 測試錯誤憑證
* 在 step2/3 最後面加上 wrong，代表對應程式使用未經過認證的憑證

### 客戶端功能
* 在 client 執行時有以下功能
    * 隨意輸入: 輸入任意字串，server 端將會收到並顯示
    * 輸入 `list_file`: server 將回傳位於 server 目錄下的所有檔案
    * 輸入 `copy_file <filename>`: server 將檔案傳送至 client 目錄下(複製的檔案將會在副檔名後加上`_copy`)
        * **輸入檔名錯誤將會造成 server 及 client shutdown**
    
---

## 設計架構與程式碼說明
### initial.c
#### 創建 SSL_CTX 實體
* 創建 TLS1.2 的 server/client
    ```cpp
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
    ```

#### 配置 SSL_CTX
* 將憑證及公鑰綁定到 SSL_CTX 中
* 載入 CA 的憑證並設定應證方式
    * `SSL_VERIFY_PEER` 要求連線的對方提供憑證
    ```cpp
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

        // 設定驗證模式及 CA 位置
        SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    ```

#### 顯示憑證
* 顯示收到的憑證資訊
    * 包含憑證本身及發行單位
    ```cpp
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
    ```

    ---

### server.c
#### 建立 socket
* 與作業1的建立連線大致相同
    ```cpp
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
    ```

#### 變數宣告及初始化與指令判別
* 呼叫 `initial.c` 的函數對 ssl 初始化
    ```cpp
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
    ```

<br><br>

#### 接收連線的無窮迴圈
* 先確認憑證驗證資訊才連線
    ```cpp
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

            // 接收 client 輸入
            count = SSL_read(ssl, receive, sizeof(receive));
            receive[count] = 0;
            printf("Received from client:\n");
            printf("%s\n\n", receive);
    ```

##### 判斷 client 輸入
* 若接到 `list_file`
    * 用 `popen` 對 shell 輸入 `ls | cat`
    * 依序用 `SSL_write` 傳送結果
    ```cpp
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
    ```
* `strtok` 分析要複製的檔案名稱
* `SSL_write(r)` 傳送複製的檔名
* `fread(c, file_size, 1, fp)` 讀出整個檔案寫入 `c`
* 在透過 `SSL_write` 傳送
    ```cpp
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
    ```

    ---

### client.c
#### 與 server 建立連線
<!-- * 根據範例程式碼 -->
*   ```cpp
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
    ```

#### 變數宣告及初始化與指令判別
* 
    ```cpp
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

    // 初始化 openssl lib
    SSL_library_init();
    hostname = argv[1];
    port = argv[2];
    ```
#### 建立連線的無窮迴圈
* 呼叫 `initial.c` 的函數對 ssl 初始化
* 先確認憑證資訊才連線
    ```cpp
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
    ```
* 只要 SSL 的 buffer 還有東西就放到 receive 中
* 若收到 "Copying_file" 表示接下來傳送的為檔案內容
    * 透過 `fwrite` 把整個 receive 寫入檔案，直到檔案結束
* 其餘的則輸出到 terminal
    ```cpp
            while ((bytes = SSL_read(ssl, receive, sizeof(receive))) != 0)
            {
                receive[bytes] = 0;
                if (strncmp(receive, "Copying_file", 12) == 0)
                {
                    char *file_name = strtok(receive, " ");
                    file_name = strtok(NULL, " ");
                    strcat(file_name, "_copy");

                    FILE *fp = fopen(file_name,"wb");
                    while ((bytes = SSL_read(ssl, receive, sizeof(receive)))!=0)
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
    ```

---

## 成果截圖
* 正常結果圖
![](https://i.imgur.com/vmyuN6p.png)
* 複製檔案結果
    * 複製前
    ![](https://i.imgur.com/aOWZ0tg.png)
    * 複製後
    ![](https://i.imgur.com/IoHDd6Y.png)
* client 憑證錯誤
    * server 第1個 close 為最開始連線
    * 紅框為對應的連線
        ![](https://i.imgur.com/J4zbUOp.png)
* server 憑證錯誤
    * client 發現憑證錯誤而中止
    ![](https://i.imgur.com/lqSlqbZ.png)

---

## 困難與⼼得
會加 `setvbuf` 是因為一開始 server 的 `printf` 如果沒有加換行就不輸出的問題，經過同學的猜測及指導，系統 buffer 可能導致此問題，所以直接關閉 stdout 的 buffer 機制，確保不會遇到。另外，在做驗證時，一開始根據 stackoverflow 的方法用 `X509_verify_cert` ，client 可以正常驗證 server 的憑證；然而，同樣的方法相反過來卻無法使用，查閱文件發現預設的 ssl 預設 client 並不會發送憑證(即便有設定SSL_CTX)，經過同學的解釋，需要在 server 用 `SSL_CTX_set_verify()` 設定模式為 `SSL_VERIFY_PEER`，才能要求連線的對方發送憑證。期中遇到的一堆莫名 segmentation fault 就換函數或換型態或是換寫法就解決了(但還是很崩潰)。

---

## 參考資料與致謝
> server
> > https://wiki.openssl.org/index.php/Simple_TLS_Server <br>

> client <br>
> > http://simplestcodings.blogspot.com/2010/08/secure-server-client-using-openssl-in-c.html <br>

> 憑證產生 <br>
> > https://blog.cssuen.tw/create-a-self-signed-certificate-using-openssl-240c7b0579d3 <br>

> c in linux 相關函數 <br>
> > https://linux.die.net/man/3 <br>

> openSSL 函數 <br>
> > https://www.openssl.org/docs/ <br>

> verify 設定 <br>
> > https://stackoverflow.com/questions/43790660/how-to-verify-any-kind-of-certificate-in-c-copenssl

> 書銘講解 verify 設定及 setvbuf