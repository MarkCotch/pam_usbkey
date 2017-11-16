CC=gcc
CFLAGS=-I. -lm

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pam_usbkey: foblib.o
	$(CC) -c -o pam_usbkey foblib.o $(CFLAGS)

test3: foblib.o
	$(CC) -o a.test3 foblib.o $(CFLAGS)
