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
  openlog("pam_usbkey", LOG_PID, LOG_AUTH);
  syslog(LOG_WARNING, _message, printParam);
  closelog();
  /*
  char _tmpString[256]={0};
  char *_timeString;
  time_t _now=time(NULL);
  _timeString=ctime(&_now);
  strtok(_timeString, "\n");
  strtok(_message, "\n");
  FILE *_FH=fopen("/var/log/pam_sshkey.log", "a");
  fprintf (_FH, "pam_usbkey: %s : %s\n", _now, _message);
  fclose (_FH); */
}

int _stringCompare (char S1[], char S2[], int len) {
  int loop;
  for (loop=0 ; loop<len ; loop++) {
      if ( S1[loop] != S2[loop] )
       return 0;
    }
  return 1;
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

char *findKeyTag(char _pubKey[]) {
  char *retval;
  int loop=strlen(_pubKey)-1;
  for ( ; loop ; loop--) {
    if (_pubKey[loop]=' ') return (&_pubKey[loop+1]);
  }
  return (NULL);
}

char *findKeyFOB(char *KeyDevice ) {
  /* const char KeyDevice=[255] = {0}; */
  char __temp_path[255]={0};
  struct dirent *_dev_Device;
  DIR *_devFP=opendir ("/dev");
  char _buff[100] = { 0 };
  char _keySig[]="-----BEGIN RSA PRIVATE KEY-----";

  DEVICELOOP: while ( _dev_Device=readdir(_devFP ) ) {
    /* Only check "Block" Devices*/
    if (_dev_Device->d_type != DT_BLK ) { continue; }
    /* Test if Media is present */
    /* Read first 32 bytes from block dev looking for SSH Key Signature.*/
    sprintf (__temp_path, "/dev/%s", _dev_Device->d_name );
    FILE *_FH=fopen( __temp_path, "r");
    if ( ! _FH) { continue; }
    fread(_buff, 1, 31, _FH);
    fclose(_FH);
    int loop;
    if (! _stringCompare( _buff, _keySig, 32) )
      continue;
    strcpy(KeyDevice, __temp_path);
    closedir(_devFP);
    return(KeyDevice);

  }
  closedir(_devFP);
  return (NULL);
}
