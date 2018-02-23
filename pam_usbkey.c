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

#define __PUK_VERSION__  "0.9.0"
#define __AUTHOR__ "Mark Coccimiglio"
#define __AUTHOR_EMAIL__ "mcoccimiglio@rice.edu"
#ifndef __DEBUG__
  #define __DEBUG__ (0)
#endif

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
#include <string.h>

#include "foblib.h"

#define __APP__ pam_usbkey
#define USBKEY_CONF /etc/usbkey.conf

char authorized_keys[]=".ssh/authorized_keys";


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

        if (__DEBUG__) l_record("DEBUG:pam_usbkey::pam_sm_authenticate called. ");

        /* Prime the Pseudo RNG. foblib.c needs this.*/
        srand(getSeed());

        if ( pam_get_item(pamh, PAM_SERVICE, (const void **)(const void *)&service ) != PAM_SUCCESS || !service || !*service) {
          l_record ("Unable to retrieve the PAM service name for :%s STOP.", service);
          return (PAM_AUTH_ERR);
        }
        if (__DEBUG__) l_record("DEBUG:We have service '%s' ...continue. ", service);

        if ( strstr(service, "sudo") || strstr (service , "su")  ) {
          if (__DEBUG__) l_record("We do not authenticate for su/sudo services.");
          return (PAM_CRED_INSUFFICIENT);
        }
        /*
        if (! _validServices(service) ) {
          if (__DEBUG__) l_record("DEBUG:Requested Service '%s' not recognized. STOP.");
          return (PAM_CRED_INSUFFICIENT);
        }
        if (__DEBUG__) l_record("DEBUG:Requested Service '%s' recognized...continue.");
        */

        if (pam_get_item( pamh, PAM_USER, (const void **)(const void *)&user ) != PAM_SUCCESS || !user || !*user) {
          char __tempNotice[256]={0};
          sprintf (__tempNotice, "pam_usbkey(%s:auth): Unable to retrieve the PAM user name, is NULL, or zero length, for '%s' ", service, user);
          /* printf ("pam_usbkey(%s:auth): Unable to retrieve the PAM user name, is NULL, or zero length, for '%s' ", service, user); */
          l_record (__tempNotice);
          return (PAM_USER_UNKNOWN);
        }
        if (__DEBUG__) l_record("DEBUG:We have user: '%s' ...continue.", user);

        if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)(const void *)&pre_token ) != PAM_SUCCESS || !pre_token || !*pre_token) {
          l_record("pam_usbkey(%s:auth): Provided token FAILED, is NULL, or Zero Length", service);
          return (PAM_CRED_INSUFFICIENT);
        }
        if (__DEBUG__) l_record("DEBUG:We have pre_token: %s ...continue.", pre_token);

        /* First test that the user is recognized by the system and has a home directory. (Sanity Checking) */
        struct passwd *_userInfo=getpwnam(user);
        if (! _userInfo) {
          char __tempNotice[256]={0};
          sprintf (__tempNotice, "pam_usbkey(%s:auth): Unable to locate user ID : '%s' STOP.", service, user);
          l_record (__tempNotice);
          return (PAM_USER_UNKNOWN);
        }
        if (__DEBUG__) l_record("DEBUG:We have validated user: '%s' ...continue.", user);

        DIR *_homeDIR;
        if (! (_homeDIR=opendir(_userInfo->pw_dir) ) ) {
          char __tempNotice[256]={0};
          sprintf(__tempNotice, "pam_usbkey(%s:auth): User home directory: '%s' not found on system.", service, _userInfo->pw_dir);
          l_record(__tempNotice);
          closedir (_homeDIR);
          return (PAM_AUTHINFO_UNAVAIL);
        }
        closedir (_homeDIR);
        if (__DEBUG__) l_record("DEBUG:we have validated home dir: '%s' ...continue.", _userInfo->pw_dir);

        /* Zero length and NULL tokens/passwords are not accepted. */
        if (! strlen(pre_token)) {
          l_record("Zero Length pre-Token. Not Accepted. '%d' STOP.", strlen(pre_token));
          return (PAM_AUTHINFO_UNAVAIL);
        }
        strcpy(token, pre_token);
        if (__DEBUG__) l_record("DEBUG:We have non-NULL token ...continue.");
        /* Sanitize input from user.  Cannot accept passwords that contain ', ", *, \ or $  */
        sanitizeString(token);
        if (__DEBUG__) l_record("DEBUG:we have sanitized token: '%s' ...continue.", token);

        /* Find, load and "try" to decrypt private key(s) using provided password */

        if (! findKeyFOB(keyFOB) ) {
          /* This represents a failure to to find an authentication
              FOB.  At this point we should fail out silently unless DEBUG.*/
          l_record("pam_usbkey(%s:auth): No authentication key present.", service);
          return (PAM_AUTHINFO_UNAVAIL);
        }
        if (__DEBUG__) sleep (5);

        sprintf (_tempString, "pam_usbkey(%s:auth): Found Authentication keyFOB: %s ", service, keyFOB);
        l_record ( _tempString );

        /* Check FOB device permissions.  og-rwx is a necessity.*/
        /* for now just do it.  We can clean this up later. */
        sprintf (_tempString, "chmod 600 %s", keyFOB);
        if (__DEBUG__) l_record ("DEBUG:set FOB to correct perms: %s", _tempString );
        system (_tempString);

        char keyLabel[512]={0};
        char *privKey;

        FILE *_ssh_keygenFP;
        char cmdString[1024]={0};
        /* sprintf(cmdString,;
           "grep \"$(ssh-keygen -P \"%s\" -y -f %s 2>&1 )\" %s/.ssh/authorized_keys /root/.ssh/authorized_keys 2> /dev/null | head -1"
           ,token, keyFOB, _userInfo->pw_dir); */
        sprintf(cmdString, "ssh-keygen -P \"%s\" -y -f %s 2>&1", token, keyFOB );
        if (__DEBUG__) l_record ("DEBUG:CMD String: %s ", cmdString);
        _ssh_keygenFP = popen(cmdString, "r");
        sleep(1);
        if (_ssh_keygenFP == NULL) {
          l_record("Failed to run command: '%s' STOP.", cmdString);
          pclose(_ssh_keygenFP);
          return(PAM_AUTHINFO_UNAVAIL);
        }
        fgets(keyLabel, 512, _ssh_keygenFP);
        pclose(_ssh_keygenFP);

        if (! keyLabel) {
          l_record("pam_usbkey(%s:auth): Derived pubkey from private returned no data.", service);
          return(PAM_AUTHINFO_UNAVAIL);
        }
        if (__DEBUG__) l_record ("DEBUG:We have keyLabel : '%s' ", keyLabel);

        if ( strstr( keyLabel, "load failed" ) || strstr( keyLabel, "incorrect passphrase" ) ) {
          char __tempNotice[256]={0};
          sprintf (__tempNotice, "pam_usbkey(%s:auth): Bad passphrase for key '%s' ", service, keyFOB);
          l_record(__tempNotice);
          return (PAM_AUTH_ERR);
        }

        /* cat .ssh/authorized_keys | ssh-keygen -lf /dev/stdin
           returns Key Fingerprints.  */
        /* extract the actual private key*/
        privKey=strtok(keyLabel, " \n");
        privKey=strtok(NULL , " \n");
        if (__DEBUG__) l_record ("DEBUG:privKey is: '%s' ", privKey);

        char *testResults;
        /* Test ~/.ssh/authorized_keys to see if our keys match. */
        char userAuthorized_keys[256];
        sprintf (userAuthorized_keys, "%s/.ssh/authorized_keys", _userInfo->pw_dir);
        if (testResults=testKeys(userAuthorized_keys, privKey)) {
          l_record ("pam_usbkey: Matching key found in '%s' ", userAuthorized_keys);
          l_record ("pam_usbkey: success for user: '%s' ", user);
          l_record ("pam_usbkey: Key authorized. Fingerprint: '%s' ", testResults );
          free (testResults);
          return (PAM_SUCCESS);
        }
        /* Test /root/.ssh/authorized_keys to see if our keys match. */
        if (testResults=testKeys("/root/.ssh/authorized_keys", privKey ) ) {
          l_record ("pam_usbkey: Matching key found in '%s' ", "/root/.ssh/authorized_keys");
          l_record ("pam_usbkey: success for user: '%s' ", user);
          l_record ("pam_usbkey: Key authorized. Fingerprint: '%s' ", testResults );
          free (testResults);
          return (PAM_SUCCESS);
        }

        l_record ("pam_usbkey: Credentials for %s not found", user );
        return (PAM_AUTHINFO_UNAVAIL);

  }

PAM_EXTERN int
  pam_sm_setcred
   (pam_handle_t *pamh,int flags,int argc, const char **argv)
    {
        if (__DEBUG__) l_record("DEBUG:pam_usbkey::pam_sm_setcred Does nothing.  Returning PAM_SUCCESS");
        return (PAM_SUCCESS);

    }
