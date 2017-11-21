include	/etc/os-release
CC=gcc
CFLAGS=-I. -lm
DEPS = foblib.h
OBJ = foblib.o

ifeq (ID_LIKE,"fedora")
	bin_dest=/usr/lib64/security/
	conf_dest=system-auth password-auth
endif

ifeq (ID_LIKE,"debian")
	bin_dest=/lib/x86_64-linux-gnu/security/
	conf_dest=common-auth
endif

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
	ifeq (ID_LIKE,"fedora")
		$@ -v -o root -g root -m 755 pam_usbkey.so /usr/lib64/security/
		perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so nullok try_first_pass/'  /etc/pam.d/system-auth
		perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so nullok try_first_pass/'  /etc/pam.d/password-auth
	endif

	ifeq(ID_LIKE,"debian")
		$@ -v -o root -g root -m 755 pam_usbkey.so /lib/x86_64-linux-gnu/security/pam_unix.so
		perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so nullok try_first_pass/'  /etc/pam.d/common-auth
	endif

uninstall:
	ifeq (ID_LIKE,"fedora")
		rm -vf /usr/lib64/security/pam_usbkey.so
		perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/system-auth
		perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/password-auth
	endif

	ifeq(ID_LIKE,"debian")
		rm -vf /lib/x86_64-linux-gnu/security/pam_unix.so
		perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/common-auth
	endif
