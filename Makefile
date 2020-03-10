all:	recvraweth sendraweth

recvraweth: recvraweth.c
	gcc -o recvraweth recvraweth.c -lpcap

sendraweth: sendraweth.c
	gcc -o sendraweth sendraweth.c -lpcap


