all:	recvraweth sendraweth

recvraweth: recvraweth.c
	gcc -o recvraweth recvraweth.c

sendraweth: sendraweth.c
	gcc -o sendraweth sendraweth.c


