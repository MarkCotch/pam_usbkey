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
#ifndef FOBLIBH
  #define FOBLIBH
  void    l_record (char *, ...);
  char   *findKeyFOB (char *);
  char   *genRandomTempDir(char *);
  int     testForBadChar(const char *);
  char   *sanitizeString( char * );
  char   *testKeys (const char *, const char *);
  int     _validServices(char *);
  typedef struct sshKey sshKey;
  struct sshKey {
     char type[25];
     char key[256];
     char tag[256];
  };

  /* I might do something with this later.
    char *authorized_keys[] = {
      "/root/.ssh/authorized_keys"
  }; */

#endif
