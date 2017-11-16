CC=gcc
CFLAGS=-I. -lm
DEPS = foblib.h
OBJ = foblib.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pam_usbkey: $(OBJ)
	$(CC) -c -o pam_usbkey foblib.o $(CFLAGS)

test3: $(OBJ)
	$(CC) -o a.test3 foblib.o $(CFLAGS)
