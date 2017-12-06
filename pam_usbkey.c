/*
    pam_usbkey -- PAM Module to use SSH Keys for LOCAL authentication.
    Copyright (c) 2017 Mark Coccimiglio

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.



*/

#define __PUK_VERSION__  "0.0.1"
#define __AUTHOR__ "Mark Coccimiglio"
#define __MYDEBUG__ (1)

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <pwd.h>
#include <dirent.h>
#include <unistd.h>

#include "foblib.h"

#define __APP__ pam_usbkey
#define USBKEY_CONF /etc/usbkey.conf
#define __DEBUG__ (1)


PAM_EXTERN int
 pam_sm_authenticate
  (pam_handle_t *pamh, int flags, int argc, const char **argv)
   {

        char keyFOB[256]={0};
        const char  *service;
        const char  *user;
        const char  *pre_token;
        char token[128]={0};
        int             rval;
        char _tempString[256]={0};



        if (__MYDEBUG__) l_record("pam_usbkey called. ");
        /* rval = pam_get_item(pamh, PAM_SERVICE, (const void **)(const void *)&service);*/
        if ( pam_get_item(pamh, PAM_SERVICE, (const void **)(const void *)&service ) != PAM_SUCCESS || !service || !*service) {
          l_record ("Unable to retrieve the PAM service name for :%s", service);
          return (PAM_AUTH_ERR);
        }
        if (__MYDEBUG__) l_record("We have service %s ", service);
        if (pam_get_item( pamh, PAM_USER, (const void **)(const void *)&user ) != PAM_SUCCESS || !user || !*user) {
          l_record ("Unable to retrieve the PAM user name for :%s", user);
          return (PAM_AUTH_ERR);
        }
        if (__MYDEBUG__) l_record("We have user: %s ", user);
        pam_get_item( pamh, PAM_AUTHTOK, (const void **)(const void *)&pre_token );
        if (__MYDEBUG__) l_record("We have pre_token: %s", pre_token);

        /* First test that the user is recognized by the system and has a home directory. (Sanity Checking) */
        struct passwd *_userInfo=getpwnam(user);
        if (! _userInfo) {
          l_record ("Unable to locate user ID : %s ", user);
          return (PAM_AUTHINFO_UNAVAIL);
        }
        if (__MYDEBUG__) l_record("We have validated user: %s ", user);

        DIR *_homeDIR;
        if (! (_homeDIR=opendir(_userInfo->pw_dir) ) ) {
          l_record("User home directory: %s not found on system.", _userInfo->pw_dir);
          closedir (_homeDIR);
          return (PAM_AUTHINFO_UNAVAIL);
        }
        closedir (_homeDIR);
        if (__MYDEBUG__) l_record("we have validated home dir: %s", _userInfo->pw_dir);

        /* Sanitize input from user.  Cannot accept passwords that contain ', ", *, \ or $  */
/*        if ( testForBadChar(token) ) {
          l_record ("Bad Character(s) in token: %s", token );
          return (PAM_AUTH_ERR);
        } */
        strcpy(token, pre_token);
        sanitizeString(token);
        if (__MYDEBUG__) l_record("we have sanitized token: %s", token);

        /* Find, load and "try" to decrypt private key(s) using provided password */

        if (! findKeyFOB(keyFOB) ) {
          /* This represents a failure to to find an authentication
              FOB.  At this point we should fail out.*/
          l_record("No Key FOB found. Returning PAM_AUTHINFO_UNAVAIL");
          return (PAM_AUTHINFO_UNAVAIL);
        }
        if (__MYDEBUG__) l_record ("Found Authentication FOB %s ", keyFOB );

        /* Check FOB device permissions.  og-rwx is a necessity.*/
        /* for now just do it.  We can clean this up later. */
        sprintf (_tempString, "chmod 600 %s", keyFOB);
        if (__MYDEBUG__) l_record ("set FOB to correct perms: %s", _tempString );
        system (_tempString);

        char keyLabel[4096]={0};

        FILE *_ssh_keygenFP;
        char cmdString[256]={0};
        /* sprintf(cmdString,
           "grep \"$(ssh-keygen -P \"%s\" -y -f %s 2>&1 )\" %s/.ssh/authorized_keys /root/.ssh/authorized_keys 2> /dev/null | head -1"
           ,token, keyFOB, _userInfo->pw_dir); */
        sprintf(cmdString, "ssh-keygen -P \"%s\" -y -f %s 2>&1", token, keyFOB );
        if (__MYDEBUG__) l_record ("CMD String: %s ", cmdString);
        _ssh_keygenFP = popen(cmdString, "r");
        sleep(2);
        if (_ssh_keygenFP == NULL) {
          l_record("Failed to run command: %s", cmdString);
          return(PAM_AUTHINFO_UNAVAIL);
        }
        /* fgets(keyLabel, sizeof(keyLabel)-1, _ssh_keygenFP); */
        fgets(keyLabel, 4095, _ssh_keygenFP);
        /* getline(&keyLabel, sizeof(keyLabel)-1, _ssh_keygenFP); */
        pclose(_ssh_keygenFP);
        if (! keyLabel) {
          l_record("Derived pubkey from private returned no data.");
          return(PAM_AUTHINFO_UNAVAIL);
        }
        if (__MYDEBUG__) l_record ("We have keyLabel : %s", keyLabel);

        if ( _stringCompare( "load failed", keyLabel, 11 ) ) {
          l_record("Bad password for user %s", user);
          return (PAM_AUTH_ERR);
        }

        ("ssh-keygen -lf /dev/stdin");

        struct sshKey fobKey;
        if (! getKey(&fobKey, keyLabel)) {
          l_record("bad keyLabel: %s", keyLabel);
          return (PAM_AUTHINFO_UNAVAIL);
        }
        if (__MYDEBUG__) l_record("We have sshKey Type: %s", fobKey.type);
        if (__MYDEBUG__) l_record("We have sshKey Key: %s", fobKey.key);
        if (__MYDEBUG__) l_record("We have sshKey Tag: %s", fobKey.tag);


        struct sshKey userKey;


        l_record ("Credentials Approved for %s:%s", user, findKeyTag(keyLabel) );

        /* cat .ssh/authorized_keys | ssh-keygen -l -f /dev/stdin */

        /* ssh-keygen -y -f mykey.pem > mykey.pub */
        /* grep "$(ssh-keygen -P PassPhrase -y -f id_rsa.test 2>&1 )" ~/.ssh/authorized_keys */

        /* Compare Private key(s) against user's public key(s) in ~/.ssh/authorized_keys */

        /* return (PAM_SUCCESS); */
        return (PAM_AUTHINFO_UNAVAIL);
  }

PAM_EXTERN int
  pam_sm_setcred
   (pam_handle_t *pamh,int flags,int argc, const char **argv)
    {
        return (PAM_SUCCESS);
    }
