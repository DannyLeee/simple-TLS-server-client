all: ex_server ex_client

args = -lssl -lcrypto
ex_server: ex_server.c
	gcc -o ex_server ex_server.c $(args)

ex_client: ex_client.c
	gcc -o ex_client ex_client.c $(args)