all: server client

args = -lssl -lcrypto
server: server.c
	gcc -o server server.c initial.c $(args)

client: client.c
	gcc -o client client.c initial.c $(args)