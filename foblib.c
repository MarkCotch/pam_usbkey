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
#ifndef FOBLIB
  #define FOBLIB
  #include <stdio.h>
  #include <string.h>
  #include <pwd.h>
  #include <dirent.h>
  #include <syslog.h>

  #ifndef NULL
    #define NULL (0)
  #endif
  #define __HASH__ sha1sum

#endif



void l_record (char* error) {
  openlog("pam_usbkey", LOG_PID, LOG_AUTH);
  syslog(LOG_NOTICE, error);
  closelog();
}

int _stringCompare (char S1[], char S2[], int len) {
  int loop;
  for (loop=0 ; loop<len ; loop++) {
      if ( S1[loop] != S2[loop] )
       return 0;
    }
  return 1;
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
