CC=gcc
CFLAGS=-I. -lm
DEPS = foblib.h
OBJ = foblib.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pam_usbkey: $(OBJ)
	$(CC) -c -o pam_usbkey $@ $< $(CFLAGS)

test%: $(OBJ)
	$(CC) -o a.test3 $@.c $< $(CFLAGS)

clean:
	rm -vf *.o a.test3
