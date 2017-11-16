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

#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <dirent.h>

void l_error (char* error) {

}

char *findKeyFOB(const char *KeyDevice ) {
  /* const char KeyDevice=[255] = {0}; */
  char __temp_path[255]={0};
  struct dirent *_dev_Device;
  DIR *_devFP=opendir ("/dev");
  char _buff[100] = { 0 };
  char _keySig[]="-----BEGIN RSA PRIVATE KEY-----";

  while ( _dev_Device=readdir(_devFP ) ) {
    /* Only check "Block" Devices*/
    if (_dev_dir->d_type != DT_BLK ) { continue; }
    /* Test if Media is present */
    /* Read first 32 bytes from block dev looking for SSH Key Signature.*/
    sprintf (__temp_path, "/dev/%s", _dev_dir->d_name );
    FILE _FH=fopen( __temp_path, "r");
    fread(_buff, 1, 31, _FH);
    fclose(_FH);
    for (int loop=0 ; loop<32 ; loop++) {
      if ( _buff[loop] != _keySig[loop] ) { continue; }
    }
    strcpy(KeyDevice, __temp_path);
    return(KeyDevice);

  }
  closedir(_devFP);
  return (NULL);
}
