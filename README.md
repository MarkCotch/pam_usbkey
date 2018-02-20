
pam_usbkey Copyright (c) 2017 Mark Coccimiglio
mcoccimiglio@rice.edu

NOTE: This package currently works but is still considered BETA.

The design of the pam module is to utilize SSH Keys for local login
authentication.  The basic premise is to install pass-phrase protected
private SSH keys on a USB fob to authenticate with a computer.  If the
corresponding Public SSH Key is present then access is granted.

Be advised that this only affects the LOCAL environment.  Kerberos tokens
are NOT created, modified or overridden.  Likewise home directory encryption
that is based on the user's password are not de-crypted.  The primary target
for this package is to eliminate the need for shared root passwords at the
system console.  If worked in conjunction with a configuration manager such as
Puppet or Ansible that makes the credentials revoke-able.  Remove the public key
from the system and the FOB no longer works.

Currently we specifically test for /dev/sr0 and ignore all CD/DVD/BlueRay disk
drives on that device.  I have not found a sufficiently reliable method to
test a drive to see if media is present before looking for a key.  I also
consider a waste to use an entire disk 600MB/4-40GB disk for a key file
that is less then 4KB in size.  Flash drive are smaller, easier to carry, and
can be partitioned to make use of the remaining storage.  Key disks should work
if you modify the code before building/installing.  In foblib.c search for "sr0"
and comment out the line.  Be advised that pam_usbkey will hit the drive each
time it is called (no "media present" test at this time).  YMMV.

GDM (graphical login): Under RedHat, GDM (graphical) logins are not supported.
I have been able to get RH to work with GDM, but it can be erratic.  Some
installs work flawlessly while others do not.  RH separates PAM into
password-auth and system-auth.  GDM uses password-auth while console logins use
system-auth.  Despite both files being the same, there does not appear to be
rhyme or reason for the difference in ability.  Further investigation is
warranted in this area.  Ubuntu does not separate PAM (common-auth) and appears
to work well with both console and graphical logins.

SSH: It seems that SSH "can" make use of pam_usbkey as well.  Under RH this is
not enabled at this time as SSH call PAM via password-auth.  On Ubuntu it does
work for the same reasons as GDM (see above).  NOTE: This is highly depended on
how the sshd daemon is configured.  If PermitRootLogin is set to "no",
"without-password", etc., then SSHD will deny the login regardless if the
Credentials are valid.  This has nothing to do with PAM or pam_usbkey.

su/sudo: su/sudo runs into permissions issues accessing the key when done from
a non-privileged user (non-"root").  We currently return PAM_CRED_INSUFFICIENT
for this service.

Required packages:
bash, perl, at, OpenSSL(-devel), sed, pam-devel

The following scripts are included in this package:

makeusbkey - make a USB Key. (Not implemented yet)

keytemp - Temporarily Places an SSH Key into a user's account (for diagnostics).  
  Not needed at this time.  Currently we authenticate against ~/.ssh/authorized_keys
  and if that fails we try against /root/.ssh/authorized_keys .
