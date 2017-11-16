CC=gcc
CFLAGS=-I. -lm
DEPS = foblib.h
OBJ = foblib.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pam_usbkey: $(OBJ)
	$(CC) -c -o pam_usbkey $@ $< $(CFLAGS)

test3.c: $(OBJ)
	$(CC) -o a.test3 $@ $< $(CFLAGS)

clean:
	ls -l *.o
