CC=gcc
CFLAGS=-I. -lm
DEPS = foblib.h
OBJ = foblib.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pam_usbkey: $(OBJ)
	$(CC) -c -fPIC $@
	$(CC) -shared -o $@.so $@.o $< $(CFLAGS)


test%: $(OBJ)
	$(CC) -o a.$@ $@.c $< $(CFLAGS)

clean:
	rm -vf *.o a.*
