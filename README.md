
pam_usbkey Copyright (c) 2017 Mark Coccimiglio
mcoccimiglio@rice.edu

NOTE: This package currently works but is still considered BETA.

The design of the pam module is to utilize SSH Keys for local login
authentication.  The basic premise is to install pass-phrase protected
private SSH keys on a USB fob to authenticate with a computer.  If the
corresponding Public SSH Key is present for root then access is granted.

Be advised that this only affects the LOCAL environment.  Kerberos tokens
are NOT created, modified or overridden.  Likewise home directory encryption 
that is based on the user's password 

Required packages:
bash, perl, at, OpenSSL(-devel), sed, pam-devel

The following scripts are included in this package:

makeusbkey - make a USB Key. (Not implemented yet)

keytemp - Temporarily Places an SSH Key into a user's account (for diagnostics).  
  Not needed at this time.  Currently we authenticate against ~/.ssh/authorized_keys
  and if that fails we try against /root/.ssh/authorized_keys .
