all:	recvraweth sendraweth bridge

recvraweth: recvraweth.c
	gcc -o recvraweth recvraweth.c -lpcap

sendraweth: sendraweth.c
	gcc -o sendraweth sendraweth.c -lpcap

bridge: utils.o bridge.o
	gcc -o bridge utils.o bridge.o

bridge.o: bridge.c
	gcc -c bridge.c

utils.o: utils.c
	gcc -c utils.c


