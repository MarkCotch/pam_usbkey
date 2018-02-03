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
#ifndef FOBLIBC
  #define FOBLIBC
  #include <stdio.h>
  #include <string.h>
  #include <time.h>
  #include <pwd.h>
  #include <dirent.h>
  #include <syslog.h>
  /* #include "foblib.h" */
  #ifndef FALSE
    #define FALSE (0)
  #endif
  #ifndef TRUE
    #define TRUE (!FALSE)
  #endif
  typedef struct sshKey sshKey;
  struct sshKey {
     char type[25];
     char key[256];
     char tag[256];
  };

#endif

void l_record (char* _message, void **printParam) {
  openlog("pam_usbkey", LOG_PID, LOG_AUTHPRIV);
  syslog(LOG_NOTICE, _message, printParam);
  closelog();

}

int testForBadChar(char _testString[]){
  /* Bad Characters  "   '   $  *   \         */
  char badChars[]={ 34, 39, 36, 42, 92, 0};
  int loop;
  // int slen=strlen(_testString)
  for (loop=0 ; _testString[loop] ; loop++){
        int iloop;
        for (iloop=0 ; badChars[iloop] ; iloop++) {
          /* syslog (LOG_WARNING, "testing _testString : %c : Value : %c",_testString[loop] ,  badChars[iloop]); */
          if (_testString[loop] == badChars[iloop] ) return ( TRUE );
        }
  }
  return ( FALSE );
}

char *sanitizeString(char _sanitizeThisString[] ){
    /* Bad Characters need to be escaped:  "  $  \     */
    char badChars[]={34, 36, 92, 0};
    char _sSTempString[256]={0};
    int sourcePos=0;
    int destPos=0;
    int loop;
    do {
        for (loop=0 ; badChars[loop] ; loop++ )
         if ( _sanitizeThisString[sourcePos] == badChars [loop] ) {
           _sSTempString[destPos]= 92;
           destPos++;
         }
    _sSTempString[destPos]=_sanitizeThisString[sourcePos];
    sourcePos++;
    destPos++;
    } while ( _sanitizeThisString[sourcePos-1] );
    strcpy(_sanitizeThisString, _sSTempString);
    return (_sanitizeThisString);
}

char *findKeyFOB(char *KeyDevice ) {
  /* const char KeyDevice=[255] = {0}; */
  char __temp_path[255]={0};
  struct dirent *_dev_Device;
  DIR *_devFP=opendir ("/dev");
  char _buff[100] = { 0 };
  char _keySig[]="PRIVATE KEY";

  DEVICELOOP: while ( _dev_Device=readdir(_devFP ) ) {
    /* Only check "Block" Devices*/
    if (_dev_Device->d_type != DT_BLK ) { continue; }
    if (strstr(_dev_Device->d_name, "sr0")) { continue; }
    /* Test if Media is present */
    FILE *_devTmpFH;
    /* Read first 31 bytes from block dev looking for SSH Key Signature.*/
    sprintf (__temp_path, "/dev/%s", _dev_Device->d_name );
    /* We use dd instead of directly opening the block device to get
       around selinux restrictions. */
    /* FILE *_FH=fopen( __temp_path, "r"); */
      char _tCmd[256]={0};
      sprintf (_tCmd, "dd if=%s bs=31 count=1 status=none", __temp_path);
      FILE *_FH=popen (_tCmd, "r");
    if ( ! _FH) { continue; }
    fread(_buff, 1, 64, _FH);
    pclose(_FH);
    int loop;
    if (! strstr( _buff, _keySig) )
      continue;
    strcpy(KeyDevice, __temp_path);
    closedir(_devFP);
    return(KeyDevice);

  }
  closedir(_devFP);
  return (NULL);
}
