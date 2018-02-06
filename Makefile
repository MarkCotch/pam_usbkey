include	/etc/os-release
CC=gcc
CFLAGS=-I. -lm
DEPS = foblib.h
OBJ = foblib.o


%.o: %.c $(DEPS)
	$(CC) -c -fPIC -o $@ $< $(CFLAGS)

pam_usbkey: $(OBJ)
	echo "$(ID_LIKE)"
	$(CC) -c -fPIC $@.c $(CFLAGS)
	$(CC) -shared -o $@.so $@.o $< $(CFLAGS)

test%: $(OBJ)
	$(CC) -o a.$@ $@.c $< $(CFLAGS)

clean:
	rm -vf *.o a.* *.so

install_"debian":
	install -v -o root -g root -m 755 pam_usbkey.so /lib/x86_64-linux-gnu/security/
	install -v -o root -g root -m 755 keytemp /usr/sbin/
	perl -i -pe 's/(^auth.*success=)(.*)( .*pam_unix.so.*$$)/$$1.($$2+1).$$3/ge' /etc/pam.d/common-auth
	perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth    sufficient    pam_usbkey.so try_first_pass/'  /etc/pam.d/common-auth

install_debian: install_"debian"

install_"fedora":
	install -v -o root -g root -m 755 pam_usbkey.so /usr/lib64/security/
	install -v -o root -g root -m 755 keytemp /usr/sbin/
	perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so try_first_pass/' /etc/pam.d/system-auth
	perl -i -pe 's/(^auth.*pam_localuser.so.*$$)/#$1/' /etc/pam.d/system-auth
	perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so try_first_pass/' /etc/pam.d/password-auth
	perl -i -pe 's/(^auth.*pam_localuser.so.*$$)/#$1/' /etc/pam.d/password-auth

install_fedora: install_"fedora"

install: install_$(ID_LIKE)

uninstall_"debian":
	rm -vf /usr/lib64/security/pam_usbkey.so
	rm -vf /usr/sbin/keytemp
	perl -i -pe 's/(^auth.*success=)(.*)( .*pam_unix.so.*$$)/$$1.($$2-1).$$3/ge' /etc/pam.d/common-auth
	perl -i -pe 's/^auth.*pam_usbkey.*\n$$//'  /etc/pam.d/common-auth

uninstall_debian: uninstall_"debian"

uninstall_"fedora":
	rm -vf /usr/lib64/security/pam_usbkey.so
	rm -vf /usr/sbin/keytemp
	perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/system-auth
	perl -i -pe 's/^#(auth.*pam_localuser.so.*$$)/$1/' /etc/pam.d/system-auth
	perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/password-auth
	perl -i -pe 's/^#(auth.*pam_localuser.so.*$$)/$1/' /etc/pam.d/password-auth

uninstall_fedora: uninstall_"fedora"

uninstall: uninstall_$(ID_LIKE)
