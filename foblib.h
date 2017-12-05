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
  void l_record (char *, ...);
  char *findKeyFOB (char *);
  char *genRandomTempDir(char *);
  int _stringCompare (char *, char *, int);
  char *findKeyTag(char *);
  int testForBadChar(const char *);
  char *sanitizeString( char * );
  struct sshKey {
    char type[25]=0;
    char key[256]=0;
    char tag[256]=0;
  };
  int getKey (struct *sshKey, char[]);
#endif
