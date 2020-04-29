## Introduce
This repo will show you an example of how to build an ssl server and client using openssl. But it is just a homework actually.

## Run
* set the CA, server, client certificate and key in `initial.h` first
```
terminal:
    make
    ./server [wrong]
    ./client 127.0.0.1 8787 [wrong]
./client:
    list_file
    copy_file <filename>
    [any string]
```
* list_file: can get file list in server folder
* copy_file <filename>: can copy file in server folder to client folder
* [any string]: server will print it

## Expected results
![](https://i.imgur.com/vmyuN6p.png)

## How to use and what can do
* client only get file list in server folder
    * and copy any of it 

**If client shutdown without error message please restart ./client**
(I really don't know why)