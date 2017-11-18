CC=gcc
CFLAGS=-I. -lm
DEPS = foblib.h
OBJ = foblib.o

%.o: %.c $(DEPS)
	$(CC) -c -fPIC -o $@ $< $(CFLAGS)

pam_usbkey: $(OBJ)
	$(CC) -c -fPIC $@.c $(CFLAGS)
	$(CC) -shared -o $@.so $@.o $< $(CFLAGS)


test%: $(OBJ)
	$(CC) -o a.$@ $@.c $< $(CFLAGS)

clean:
	rm -vf *.o a.* *.so

install:
	$@ -v -o root -g root -m 755 pam_usbkey.so /usr/lib64/security/
	perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so nullok try_first_pass/'  /etc/pam.d/system-auth
	perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so nullok try_first_pass/'  /etc/pam.d/password-auth
#	perl -i -pe 's/(^auth.*password-auth.*$$)/$$1\nauth       sufficient   pam_usbkey.so nullok try_first_pass/'  /etc/pam.d/sshd
uninstall:
	rm -vf /usr/lib64/security/pam_usbkey.so
	perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/system-auth
	perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/sshd
