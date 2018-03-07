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
  #include <stdlib.h>
  #include <stdarg.h>
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
  #ifndef __DEBUG__
    #define __DEBUG__ config.debug
  #endif
  typedef struct sshKey sshKey;
  struct sshKey {
     char type[25];
     char key[256];
     char tag[256];
  };

  struct configuration {
    int checkRootKeys;
    char authorized_keys[256];
    char rootAuthorized_keys[256];
    char deviceNoExamine[256];
    int debug;
  };
  #define USBKEY_CONF "/etc/usbkey.conf"
#endif

extern struct configuration config;

/* void    syslog (LOG_NOTICE, char *, ...); */


struct configuration *loadConfig(struct configuration *cfg) {
  char linefromCFG[512];
  char __buff[512];
  char *_key;
  char *_value;
  if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:foblib: Loading Config file.");
  FILE *cfgFH=fopen(USBKEY_CONF, "r");
  if (! cfgFH) return (NULL);
  while ( fgets (linefromCFG, sizeof(linefromCFG), cfgFH )) {
    strtok(linefromCFG, "\n");
    if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:foblib: have line from config file '%s' ", linefromCFG);
    strcpy (__buff, linefromCFG);
    if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:foblib: have buff '%s' ", __buff);
    /* remove comments and whitespace lines*/
    strtok(linefromCFG, "#");
    if (strlen(linefromCFG)<4) continue;
    if (! linefromCFG[0])      continue;
    if (linefromCFG[0]=='#')   continue;
    if (linefromCFG[0]=='\n')  continue;

    /* breakout key/value pairs*/
    _key=strtok(linefromCFG, "=");
    if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:foblib:Key='%s'",_key);
    _value=strtok(0, "=");
    if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:foblib:Value='%s'",_value);
    if (! _value) continue;
    /* sscanf(_key, "%s", __buff);
    strcpy(_key,__buff);
    sscanf(_value, "%s", __buff);
    strcpy(_value,__buff); */
    if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:foblib:Sanitized Key='%s' Value='%s'", _key, _value);
    /* NULL keys are ignored.*/
    if (! _key[0]) continue;

    /* Test for config choices*/
    if (strstr("checkRootKeys", _key)) {
      if (strstr(_value, "y") || strstr(_value, "Y") || strstr(_value, "1") ) {
        if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG: set TRUE checkRootKeys='%s' ", _value);
        cfg->checkRootKeys=1;
      }
      if (strstr(_value, "n") || strstr(_value, "n") || strstr(_value, "0") ) {
        if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG: set TRUE checkRootKeys='%s' ", _value);
        cfg->checkRootKeys=0;
      }
      continue;
    }
    if (strstr("debug", _key)) {
      if (strstr(_value, "y") || strstr(_value, "Y") || strstr(_value, "1") ) {
        if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG: set TRUE debug='%s' ", _value);
        cfg->debug=1;
      }
      if (strstr(_value, "n") || strstr(_value, "n") || strstr(_value, "0") ) {
        if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG: set FALSE debug='%s' ", _value);
        cfg->debug=0;
      }
      continue;
    }
    if (strstr("authorized_keys", _key)) {
      if (_value[0]) {
        if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG: set authorized_keys='%s' ", _value);
        sscanf (_value, "%s", cfg->authorized_keys);
        /* strcpy(cfg->authorized_keys, _value); */
      }
      continue;
    }
    if (strstr("rootAuthorized_keys", _key)) {
      if (_value[0]) {
        if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG: set rootAuthorized_keys='%s' ", _value);
        /* strcpy(cfg->rootAuthorized_keys, _value); */
        sscanf (_value, "%s", cfg->rootAuthorized_keys);
      }
      continue;
    }
    if (strstr("deviceNoExamine", _key)) {
      if (_value[0]) {
        if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG: set deviceNoExamine='%s' ", _value);
        strcpy(cfg->deviceNoExamine, _value);
      }
      continue;
    }
  }

  fclose(cfgFH);
  if (__DEBUG__) syslog(LOG_NOTICE, "configuration->checkRootKeys: %d ", cfg->checkRootKeys);
  if (__DEBUG__) syslog(LOG_NOTICE, "configuration->debug: %d ", cfg->debug);
  if (__DEBUG__) syslog(LOG_NOTICE, "DEBUG:foblib: Config file loaded. ");
  return (cfg);
};

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

char *findKeyFOB(char *KeyDevice, char badlist[] ) {
  /* const char KeyDevice=[255] = {0}; */
  char __temp_path[255]={0};
  struct dirent *_dev_Device;
  DIR *_devFP=opendir ("/dev");
  char _buff[100] = { 0 };
  char _keySig[]="PRIVATE KEY";

  DEVICELOOP: while ( _dev_Device=readdir(_devFP ) ) {
    /* Only check "Block" Devices*/
    if (_dev_Device->d_type != DT_BLK ) { continue; }
    if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:Checking Device: %s in list '%s' ", _dev_Device->d_name, badlist );
    if (badlist && badlist[0] && strstr(badlist, _dev_Device->d_name)) {
      if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:Found device %s in list '%s' ...skipping. ", _dev_Device->d_name, badlist);
      continue;
    }
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

int getSeed(void) {
  int loop=0;
  union {
    int i;
    char c[sizeof(int)];
  } seedValue;
  FILE *RSFH=fopen("/dev/urandom", "r");
  for (loop=0 ; loop < sizeof(int) ; loop++) {
		seedValue.c[loop]=fgetc(RSFH);
	}
  fclose(RSFH);
  return (seedValue.i);
}

char *testKeys (const char *authorized_keys, const char *FOBKEY) {
  FILE *authFP;
  char pubKeyToTest[512]={0};

  /* opening file for reading */
  authFP = fopen(authorized_keys , "r");
  if(authFP == NULL) {
    if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG: Error opening file %s ", authorized_keys);
    return(NULL);
  }
  while ( fgets ( pubKeyToTest, 512, authFP) !=NULL ) {
    if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:Trying Key: '%s' ",  pubKeyToTest);
    if ( ! strlen(pubKeyToTest) ) {
      syslog (LOG_NOTICE, "pubKeyToTest length NULL...continue.", NULL);
      continue;
    }
    strtok(pubKeyToTest, "\n");
    if(strstr(pubKeyToTest, FOBKEY) != NULL) {
      /* Key matches.  Record key signature and return PAM_SUCCESS*/
      fclose (authFP);

      FILE *_tempPubKeyFH;
      char *_tmpTimeString;
      char _tmpfile[256]={0};
      int rval;

      rval=rand();
      time_t _now=time(NULL);
      sprintf (_tmpfile, "/tmp/.pam_usbkey-%d-%d", (int) _now, rval);

      if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:Creating temp file '%s'", _tmpfile);
      if ( (_tempPubKeyFH=fopen(_tmpfile, "w")) == NULL ) {
        syslog (LOG_NOTICE, "Unable to open file '%s' for write", _tempPubKeyFH);
        fclose (_tempPubKeyFH);
        fclose (authFP);
        return (NULL);
      }

      fputs (pubKeyToTest, _tempPubKeyFH);
      fclose (_tempPubKeyFH);

      FILE *_tGetSigFH;
      /* char _sVal[512]={0}; */
      char *_sVal=malloc(512 * sizeof(char));
      char getSigCmd[1024]={0};
      /* strtok(pubKeyToTest, "\n"); */
      sprintf(getSigCmd, "/usr/bin/ssh-keygen -lf %s " , _tmpfile);
      if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG:Running: '%s' ", getSigCmd);

      _tGetSigFH=popen(getSigCmd, "r");
      /* if (__DEBUG__) sleep (1); */
      if ( _tGetSigFH == NULL ) { syslog (LOG_NOTICE, "Failed to obtain key Fingreprint.", NULL);
        pclose (_tGetSigFH);
        return (NULL);
      }
      if (__DEBUG__) {
        if (_tGetSigFH) syslog (LOG_NOTICE, "DEBUG:Command run successfull.", NULL);
      }

      fgets( _sVal, 512, _tGetSigFH );
      strtok(_sVal, "\n");

      /* syslog (LOG_NOTICE, "Key authorized for user: '%s' ", user); */
      /* syslog (LOG_NOTICE, "Key authorized. Fingerprint: '%s' ", _sVal ); */
      pclose (_tGetSigFH);

      if (__DEBUG__) syslog (LOG_NOTICE, "DEBUG: Removing temp file %s", _tmpfile);
      if (remove (_tmpfile)) syslog (LOG_NOTICE, "Removing temp file %s FAILED.", (void**) _tmpfile);

      return (_sVal);

    }
  }

/* no matching key found */
return (NULL);


}

int _validServices(char *requestedService) {
  char *_validServices[]={"ssh", "login", "gdm-password"};
  return (1);
}
