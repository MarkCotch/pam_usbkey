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

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "foblib.h"

#define __APP__ pam_usbkey
#define USBKEY_CONF /etc/usbkey.conf



PAM_EXTERN int
 pam_sm_authenticate
  (pam_handle_t *pamh, int flags, int argc, const char **argv)
   {

        char keyFOB[256]={0};
        int             rval;

        /* rval = pam_get_item(pamh, PAM_SERVICE, (const void **)(const void *)&service);*/

        if (rval != PAM_SUCCESS)
        {
                l_error("Unable to retrieve the PAM service name.\n");
                return (PAM_AUTH_ERR);
        }

        /* Find, load and "try" to decrypt private key(s) using provided password */

        if (! findKeyFOB(keyFOB) ) {
          /* This represents a failure to to find an authentication
              FOB.  At this point we should fail out.*/
          return (PAM_AUTHINFO_UNAVAIL);
        }

        /* Check FOB device permissions.  og-rwx is a necessity.*/
        /* for now just do it.  We can clean this up later. */
        char _tempString[256]={0};
        sprintf (_tempString, "chmod 600 %s", keyFOB);
        system (_tempString);

        char keyLabel[128]={0};

          FILE *_ssh_keygenFP;
          _ssh_keygenFP = popen("grep \"$(ssh-keygen -P PassPhrase -y -f /dev/vdb1 2>&1 )\" /root/.ssh/authorized_keys | cut -d' ' -f3", "r");
          if (_ssh_keygenFP == NULL) {
            printf("Failed to run command\n" );
            return(PAM_AUTHINFO_UNAVAIL);
          }
          fgets(buff, sizeof(keyLabel)-1, cmdFP);
          pclose(_ssh_keygenFP)
          if (! keyLabel) return(PAM_AUTHINFO_UNAVAIL);



        /* ssh-keygen -y -f mykey.pem > mykey.pub */
        /* grep "$(ssh-keygen -P PassPhrase -y -f id_rsa.test 2>&1 )" ~/.ssh/authorized_keys */

        /* Compare Private key(s) against user's public key(s) in ~/.ssh/authorized_keys */

  }

PAM_EXTERN int
  pam_sm_setcred
   (pam_handle_t *pamh,int flags,int argc, const char **argv)
    {
        return (PAM_SUCCESS);
    }
