%define		name		pam_usbkey
%define		version		0.9.3
%define		release		5%{?dist}

%global		__os_install_post	%{nil}

Name:		%{name}
Version:	%{version}
Release:	%{release}
Group:		System Environment/Base
Summary:	The design of the pam module is to utilize SSH Keys for local login authentication. The basic premise is to install pass-phrase protected private SSH keys on a USB fob to authenticate with a computer. If the corresponding Public SSH Key is present for the requested user ID then access is granted.

License:	GPL3+
URL:		https://github.com/MarkCotch/pam_usbkey
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	pam pam-devel gcc
Requires:	perl pam
Packager:	Mark Coccimiglio <mark@coccimiglio.net, mcoccimiglio@rice.edu>
BuildArch:	x86_64

%description
The design of the pam module is to utilize SSH Keys for local login authentication. The basic premise is to install pass-phrase protected private SSH keys on a USB fob to authenticate with a computer. If the corresponding Public SSH Key is present then access is granted.

NOTE: pam_usbkey.so only works with passphrase protected/encrypted SSH keys. NULL/unencrypted passwords/passphrases are ignored.

Be advised that this only affects the LOCAL environment. Kerberos tokens are NOT created, modified or overridden. Likewise home directory encryption that is based on the user's password are not de-crypted. The primary target for this package is to eliminate the need for shared root passwords at the system console. If worked in conjunction with a configuration manager such as Puppet or Ansible that makes the credentials revoke-able. Remove the public key from the system and the FOB no longer works.


%prep
%setup -q


##%build
##make

%install
mkdir -p %{buildroot}/usr/lib64/security/ 
mkdir -p %{buildroot}/etc 
mkdir -p %{buildroot}/usr/sbin
mkdir -p %{buildroot}/usr/share/man/man8 

install -v -m 755 pam_usbkey.so %{buildroot}/usr/lib64/security/
install -v -m 755 keytemp       %{buildroot}/usr/sbin/
install -v -m 755 usbkey.conf   %{buildroot}/etc/usbkey.conf
install -v -m 644 pam_usbkey.8  %{buildroot}/usr/share/man/man8/

%post
grep -q pam_usbkey.so /etc/pam.d/system-auth   || \
   perl -i -pe 's/(^auth.*pam_unix.so.*$)/$1\nauth        sufficient    pam_usbkey.so /' /etc/pam.d/system-auth
grep -q pam_usbkey.so /etc/pam.d/password-auth || \
   perl -i -pe 's/(^auth.*pam_unix.so.*$)/$1\nauth        sufficient    pam_usbkey.so /' /etc/pam.d/password-auth

%postun
(( $1 )) || perl -i -pe 's/^.*%{name}.*\n$//' /etc/pam.d/system-auth
(( $1 )) || perl -i -pe 's/^.*%{name}.*\n$//' /etc/pam.d/password-auth


%files
/usr/lib64/security/pam_usbkey.so
/usr/sbin/keytemp
/etc/usbkey.conf
/usr/share/man/man8/pam_usbkey.8

%license LICENSE

%doc



#%changelog
#* pam_usbkey V0.9.3 
