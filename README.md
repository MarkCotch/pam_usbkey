
pam_usbkey Copyright (c) 2017 Mark Coccimiglio
mcoccimiglio@rice.edu

NOTE: This package currently works but is still considered BETA.

The design of the pam module is to utilize SSH Keys for local login
authentication.  The basic premise is to install pass-phrase protected
private SSH keys on a USB fob to authenticate with a computer.  If the
corresponding Public SSH Key is present then access is granted.

NOTE: pam_usbkey.so only works with passphrase protected/encrypted SSH keys.
  NULL/unencrypted passwords/passphrases are ignored.

Be advised that this only affects the LOCAL environment.  Kerberos tokens
are NOT created, modified or overridden.  Likewise home directory encryption
that is based on the user's password are not de-crypted.  The primary target
for this package is to eliminate the need for shared root passwords at the
system console.  If worked in conjunction with a configuration manager such as
Puppet or Ansible that makes the credentials revoke-able.  Remove the public key
from the system and the FOB no longer works.

Currently we specifically test for /dev/sr{0,1,2,3} and ignore all CD/DVD/BlueRay
disk drives on that device.  I have not found a sufficiently reliable method to
test a drive to see if media is present before looking for a key.  I also
consider a waste to use an entire disk 600MB/4-40GB disk for a key file
that is less then 4KB in size.  Flash drive are smaller, easier to carry, and
can be partitioned to make use of the remaining storage.  This is adjustable in
the configuration file. Be advised that pam_usbkey will hit the drive each
time it is called (no "media present" test at this time).  YMMV.

GDM (graphical login): Under RedHat, GDM (graphical) logins ARE now supported.
RH separates PAM into password-auth and system-auth. GDM (ssh, and other user
credential challenges) uses password-auth while console logins use
system-auth.  Ubuntu does not separate PAM (common-auth) and appears
to work well with both console and graphical logins.

SSH: It seems that SSH "can" make use of pam_usbkey as well.
NOTE: This is highly depended on how the sshd daemon is configured.  
If PermitRootLogin is set to "no", "without-password", etc., then SSHD 
will deny the login regardless if the Credentials are valid.  This has
nothing to do with PAM or pam_usbkey.

su/sudo: su/sudo runs into permissions issues accessing the key when done from
a non-privileged user (non-"root").  We currently return PAM_CRED_INSUFFICIENT
for these service.

Required packages:
bash, perl, at, openssl(-devel), sed, pam-devel (el) libpam0g-dev (deb)

The following scripts are included in this package:

makeusbkey - make a USB Key. (Not implemented yet)

keytemp - Temporarily Places an SSH Key into a user's account (for diagnostics).  
  Not needed at this time.  Currently we authenticate against ~/.ssh/authorized_keys
  and if that fails we try against /root/.ssh/authorized_keys .  I have debated the 
  security implication of this and have determined them to be in consequential. 
  pam_usbkey.so fingerprints the credentials and logs sufficiently to establish who 
  is actually logging in to the system.  If you don't trust your root ssh public keys
  you have bigger problems.  The behaviour can be adjusted in the configuration file by 
  setting checkRootKeys=No .
