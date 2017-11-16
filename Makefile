CC=gcc
CFLAGS=-I. -lm
DEPS = foblib.h
OBJ = foblib.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pam_usbkey: $(OBJ)
	$(CC) -c -fPIC $@.c $(CFLAGS)
	$(CC) -shared -o $@.so $@.o $(CFLAGS)


test%: $(OBJ)
	$(CC) -o a.$@ $@.c $< $(CFLAGS)

clean:
	rm -vf *.o a.* *.so

install:
	perl -pe 's/(^auth.*pam_unix.so.*$)/auth        sufficient    pam_usbkey.so nullok try_first_pass\n$1/'  /etc/pam.d/system-auth

uninstall:
	perl -pe 's/^auth.*pam_usbkey.*\n$//' /etc/pam.d/system-auth
