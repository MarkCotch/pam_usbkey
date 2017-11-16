CC=gcc
CFLAGS=-I. -lm

pam_usbkey: foblib.o
	$(CC) -o pam_usbkey foblib.o $(CFLAGS)

test3: foblib.o
	$(CC) -o a.test3 foblib.o $(CFLAGS)
