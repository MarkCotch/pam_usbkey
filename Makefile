include	/etc/os-release
NAME = pam_usbkey
VERSION= 0.9.3
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

test%:
	$(CC) -o a.$@ $@.c $< $(CFLAGS)

clean:
	rm -vf *.o a.* *.so rpm/*
	test -d rpm && rmdir rpm

install: install_bin install_conf

install_bin: install_bin_$(ID_LIKE)

install_conf: install_conf_$(ID_LIKE)

install_bin_"debian":
	install -v -o root -g root -m 755 pam_usbkey.so /lib/x86_64-linux-gnu/security/
	install -v -o root -g root -m 755 keytemp /usr/sbin/

install_conf_"debian":
	test -s /etc/usbkey.conf || install -v -o root -g root -m 644 usbkey.conf /etc/usbkey.conf
	install -v -o root -g root -m 755 usbkey /usr/share/pam-configs/usbkey
	pam-auth-update --package
#	perl -i -pe 's/(^auth.*success=)(.*)( .*pam_unix.so.*$$)/$$1.($$2+1).$$3/ge' /etc/pam.d/common-auth
#	perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth    sufficient    pam_usbkey.so try_first_pass/'  /etc/pam.d/common-auth

install_bin_"fedora":
	install -v -o root -g root -m 755 pam_usbkey.so /usr/lib64/security/
	install -v -o root -g root -m 755 keytemp /usr/sbin/

install_conf_"fedora":
	test -s /etc/usbkey.conf || install -v -o root -g root -m 644 usbkey.conf /etc/usbkey.conf
	perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so /' /etc/pam.d/system-auth
#	perl -i -pe 's/(^auth.*pam_localuser.so.*$$)/#$1/' /etc/pam.d/system-auth
	perl -i -pe 's/(^auth.*pam_unix.so.*$$)/$$1\nauth        sufficient    pam_usbkey.so /' /etc/pam.d/password-auth
#	perl -i -pe 's/(^auth.*pam_localuser.so.*$$)/#$1/' /etc/pam.d/password-auth

source: pam_usbkey
	mkdir -vp rpm           $(NAME)-$(VERSION)
	cp    -v  LICENSE       $(NAME)-$(VERSION)/
	cp    -v  keytemp       $(NAME)-$(VERSION)/
	cp    -v  pam_usbkey.so $(NAME)-$(VERSION)/
	cp    -v  README.md     $(NAME)-$(VERSION)/
	cp    -v  usbkey.conf   $(NAME)-$(VERSION)/
	cp    -v  pam_usbkey-0.9.3.spec        rpm/ 
	tar    czvf rpm/$(NAME)-$(VERSION).tar.gz  $(NAME)-$(VERSION)/

uninstall: uninstall_bin uninstall_conf

uninstall_bin: uninstall_bin_$(ID_LIKE)

uninstall_conf: uninstall_conf_$(ID_LIKE)

uninstall_bin_"debian":
	rm -vf /usr/lib64/security/pam_usbkey.so
	rm -vf /usr/sbin/keytemp


uninstall_conf_"debian":
	pam-auth-update --remove usbkey
	rm -vf /usr/share/pam-configs/usbkey
	rm -vf /etc/usbkey.conf
#	perl -i -pe 's/(^auth.*success=)(.*)( .*pam_unix.so.*$$)/$$1.($$2-1).$$3/ge' /etc/pam.d/common-auth
#	perl -i -pe 's/^auth.*pam_usbkey.*\n$$//'  /etc/pam.d/common-auth

uninstall_bin_"fedora":
	rm -vf /usr/lib64/security/pam_usbkey.so
	rm -vf /usr/sbin/keytemp

uninstall_conf_"fedora":
	rm -vf /etc/usbkey.conf
	perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/system-auth
	perl -i -pe 's/^#(auth.*pam_localuser.so.*$$)/$1/' /etc/pam.d/system-auth
	perl -i -pe 's/^auth.*pam_usbkey.*\n$$//' /etc/pam.d/password-auth
	perl -i -pe 's/^#(auth.*pam_localuser.so.*$$)/$1/' /etc/pam.d/password-auth
