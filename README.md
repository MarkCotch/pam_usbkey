
pam_usbkey Copyright (c) 2017 Mark Coccimiglio
mcoccimiglio@rice.edu

The design of the pam module is to utilize SSH Keys for local login
authentication.  The basic premise is to install pass-phrase protected
private SSH keys on a USB fob to authenticate with a computer.  If the
corresponding Public SSH Key is present for the requested user ID then
access is granted.

Required packages:
BASH, PERL, AT, OpenSSL(-devel), SED, libssh2(-devel)

The following scripts are included in this package:

makeusbkey - make a USB Key.

<<<<<<< HEAD
keytemp - Temporarily Places an SSH Key into a user's account (for diagnostics).
=======
keytemp - Places an SSH Key into a users account (for diagnostics).
>>>>>>> 5b696bae8ea9c8d8ebb7a3bc2e15df9470bcd0a0
