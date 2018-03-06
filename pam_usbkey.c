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

#ifndef __PUK_VERSION__
  #define __PUK_VERSION__  "0.9.2"
  #define __PUK_VERSION_D__ 0.9.2
  #define __AUTHOR__ "Mark Coccimiglio"
  #define __AUTHOR_EMAIL__ "mcoccimiglio@rice.edu"
#endif
#ifndef __DEBUG__
  #define __DEBUG__ config.debug
#endif

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <pwd.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "foblib.h"

#define __APP__ pam_usbkey
#define USBKEY_CONF "/etc/usbkey.conf"

struct configuration config = { 1, ".ssh/authorized_keys", "/root/.ssh/authorized_keys", "sr0 sr1 sr2 sr3", 0 } ;

PAM_EXTERN int
 pam_sm_authenticate
  (pam_handle_t *pamh, int flags, int argc, const char *argv[])
   {

        char keyFOB[256]={0};
        const char  *service;
        const char  *user;
        const char  *pre_token;
        char token[128]={0};
        int             rval;
        char _tempString[256]={0};

        /* load configuration at USBKEY_CONF This needs some work. */


        if (! loadConfig( &config ) ) {
          if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey:pam_sm_authenticate: Unable to load usb_key.conf file.  Using defaults");
        }
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey::pam_sm_authenticate called. Version: %s ", __PUK_VERSION__ );
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey:pam_sm_authenticate:debug=%d",config.debug);
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey:pam_sm_authenticate:checkRootKeys=%d",config.checkRootKeys);
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey:pam_sm_authenticate:authorized_keys=%s",config.authorized_keys);
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey:pam_sm_authenticate:rootAuthorized_keys=%s",config.rootAuthorized_keys);
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey:pam_sm_authenticate:deviceNoExamine=%s",config.deviceNoExamine);



        /* Prime the Pseudo RNG. foblib.c needs this.*/
        srand(getSeed());

        if ( pam_get_item(pamh, PAM_SERVICE, (const void **)(const void *)&service ) != PAM_SUCCESS || !service || !*service) {
          syslog (LOG_NOTICE, "Unable to retrieve the PAM service name for :%s STOP.", service);
          return (PAM_AUTH_ERR);
        }
        if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG:We have service '%s' ...continue. ", service);

        if ( strstr(service, "sudo") || strstr (service , "su")  ) {
          if (__DEBUG__) syslog (LOG_NOTICE, "We do not authenticate for su/sudo services.");
          return (PAM_CRED_INSUFFICIENT);
        }


        if (pam_get_item( pamh, PAM_USER, (const void **)(const void *)&user ) != PAM_SUCCESS || !user || !*user) {
          /* User name is not set.  Tell pam to get user name */
          if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:No user provided,  Asking PAM for username.");
          if ( pam_get_user (pamh, &user, NULL) != PAM_SUCCESS || !user || !*user ) {
           syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Unable to retrieve the PAM user name, is NULL, or zero length, for '%s' ", service, user);
           return (PAM_USER_UNKNOWN);
         }
        }

        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:We have user: '%s' ...continue.", user);

        if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)(const void *)&pre_token ) != PAM_SUCCESS || !pre_token || !*pre_token) {
          /* Token not set.  Ask PAM for authtok. */
          if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:No token provided,  Asking PAM for authtok");
          if (pam_get_authtok(pamh, PAM_AUTHTOK, &pre_token, NULL ) != PAM_SUCCESS || !pre_token || !*pre_token) {
            syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Provided token FAILED, is NULL, or Zero Length", service);
            return (PAM_CRED_INSUFFICIENT);
          }
        }
        /* This debug option is dangerous/insecure to keep in the live source.  If needed uncomment and rebuild binary */
        /*if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:We have pre_token: %s ...continue.", pre_token);*/

        /* First test that the user is recognized by the system and has a home directory. (Sanity Checking) */
        struct passwd *_userInfo=getpwnam(user);
        if (! _userInfo) {
          char __tempNotice[256]={0};
          sprintf (__tempNotice, "pam_usbkey(%s:auth): Unable to locate user ID : '%s' STOP.", service, user);
          syslog (LOG_NOTICE, __tempNotice);
          return (PAM_USER_UNKNOWN);
        }
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:We have validated user: '%s' ...continue.", user);

        DIR *_homeDIR;
        if (! (_homeDIR=opendir(_userInfo->pw_dir) ) ) {
          char __tempNotice[256]={0};
          sprintf(__tempNotice, "pam_usbkey(%s:auth): User home directory: '%s' not found on system.", service, _userInfo->pw_dir);
          syslog (LOG_NOTICE, __tempNotice);
          closedir (_homeDIR);
          return (PAM_AUTHINFO_UNAVAIL);
        }
        closedir (_homeDIR);
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:we have validated home dir: '%s' ...continue.", _userInfo->pw_dir);

        /* Zero length and NULL tokens/passwords are not accepted. */
        if (! strlen(pre_token)) {
          syslog (LOG_NOTICE, "Zero Length pre-Token. Not Accepted. '%d' STOP.", strlen(pre_token));
          return (PAM_AUTHINFO_UNAVAIL);
        }
        strcpy(token, pre_token);
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:We have non-NULL token ...continue.");
        /* Sanitize input from user.  Cannot accept passwords that contain ', ", *, \ or $  */
        sanitizeString(token);
        /* This is a dangerous/insecure debug note. Uncomment and rebuild if needed. */
        /* if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:we have sanitized token: '%s' ...continue.", token); */
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:we have sanitized token ...continue.");
        /* Find, load and "try" to decrypt private key(s) using provided password */

        if (! findKeyFOB(keyFOB, config.deviceNoExamine) ) {
          /* This represents a failure to to find an authentication
              FOB.  At this point we should fail out silently unless DEBUG.*/
          syslog (LOG_NOTICE, "pam_usbkey(%s:auth): No authentication key present.", service);
          return (PAM_AUTHINFO_UNAVAIL);
        }
        if (__DEBUG__) sleep (5);

        syslog (LOG_NOTICE,"pam_usbkey(%s:auth): Found Authentication keyFOB: %s ", service, keyFOB);

        /* Check FOB device permissions.  og-rwx is a necessity.*/
        /* for now just do it.  We can clean this up later. */
        sprintf (_tempString, "chmod 600 %s", keyFOB);
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:set FOB to correct perms: %s", _tempString );
        system (_tempString);

        char keyLabel[512]={0};
        char *privKey;

        FILE *_ssh_keygenFP;
        char cmdString[1024]={0};
        /* sprintf(cmdString,;
           "grep \"$(ssh-keygen -P \"%s\" -y -f %s 2>&1 )\" %s/.ssh/authorized_keys /root/.ssh/authorized_keys 2> /dev/null | head -1"
           ,token, keyFOB, _userInfo->pw_dir); */
        sprintf(cmdString, "ssh-keygen -P \"%s\" -y -f %s 2>&1", token, keyFOB );
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:CMD String: %s ", cmdString);
        _ssh_keygenFP = popen(cmdString, "r");
        sleep(1);
        if (_ssh_keygenFP == NULL) {
          syslog (LOG_NOTICE, "Failed to run command: '%s' STOP.", cmdString);
          pclose(_ssh_keygenFP);
          return(PAM_AUTHINFO_UNAVAIL);
        }
        fgets(keyLabel, 512, _ssh_keygenFP);
        pclose(_ssh_keygenFP);

        if (! keyLabel) {
          syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Derived pubkey from private returned no data.", service);
          return(PAM_AUTHINFO_UNAVAIL);
        }
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:We have keyLabel : '%s' ", keyLabel);

        if ( strstr( keyLabel, "load failed" ) || strstr( keyLabel, "incorrect passphrase" ) ) {
          syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Bad passphrase for key '%s' ", service, keyFOB);
          return (PAM_AUTH_ERR);
        }

        /* cat .ssh/authorized_keys | ssh-keygen -lf /dev/stdin
           returns Key Fingerprints.  */
        /* extract the actual private key*/
        privKey=strtok(keyLabel, " \n");
        privKey=strtok(NULL , " \n");
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:privKey is: '%s' ", privKey);

        char *testResults;
        /* Test ~/.ssh/authorized_keys to see if our keys match. */
        char userAuthorized_keys[256];
        sprintf (userAuthorized_keys, "%s/%s", _userInfo->pw_dir, config.authorized_keys);
        if (testResults=testKeys(userAuthorized_keys, privKey)) {
          syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Matching key found in '%s' ", service, userAuthorized_keys);
          syslog (LOG_NOTICE, "pam_usbkey(%s:auth): success for user: '%s' ", service, user);
          syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Key authorized. Fingerprint: '%s' ", service, testResults );
          free (testResults);
          return (PAM_SUCCESS);
        }
        /* Test /root/.ssh/authorized_keys to see if our keys match. */
        if (config.checkRootKeys) {
          if (testResults=testKeys(config.rootAuthorized_keys, privKey ) ) {
            syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Matching key found in '%s' ", service, "/root/.ssh/authorized_keys");
            syslog (LOG_NOTICE, "pam_usbkey(%s:auth): success for user: '%s' ", service, user);
            syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Key authorized. Fingerprint: '%s' ", service, testResults );
            free (testResults);
            return (PAM_SUCCESS);
          }
        }
        syslog (LOG_NOTICE, "pam_usbkey(%s:auth): Credentials for %s not found", service, user );
        return (PAM_AUTHINFO_UNAVAIL);

  }

PAM_EXTERN int
  pam_sm_setcred
   (pam_handle_t *pamh,int flags,int argc, const char **argv)
    {
      /* load configuration at USBKEY_CONF */
      if (! loadConfig( &config ) ) {
        if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey:pam_sm_authenticate: Unable to load usb_key.conf file.  Using defaults");
      }
      if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:pam_usbkey::pam_sm_setcred Does nothing.  Returning PAM_SUCCESS");
      return (PAM_SUCCESS);

    }


PAM_EXTERN int
    pam_sm_acct_mgmt
    (pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
    	return (PAM_SUCCESS);
}

PAM_EXTERN int
  pam_sm_open_session
     (pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
    	  return (PAM_SUCCESS);
}

PAM_EXTERN int
  pam_sm_close_session
    (pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
    	return (PAM_SUCCESS);
}

PAM_EXTERN int
  pam_sm_chauthtok
    (pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
      return (PAM_SERVICE_ERR);
}
