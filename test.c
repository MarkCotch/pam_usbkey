/*

  The file is for testing and experimentation.

*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <dirent.h>

struct passwd *userID;


int main( int argc, char **argv )
  {

    /*userID=getpwnam(argv[1]);
     printf ("%s \n", userID->pw_dir); */
    DIR *_devFP;
    FILE *_blockDev;
    char _buff[100];
    _devFP=opendir ("/dev");
    struct dirent *_dev_dir;

    /* Note: ls -l /sys/dev/block/8* */
    while ( _dev_dir=readdir(_devFP) ) {
      if (_dev_dir->d_type == DT_BLK) {
       printf ("iNode %lu\t: Filename  %s \t: Type: %d \n", _dev_dir->d_ino, _dev_dir->d_name, _dev_dir->d_type);
       /* _blockDev=fopen ("/dev/&_dev_dir->d_name", "r");
       fread(_buff, 3, 1, _blockDev);*/
       printf ("/dev/%s \n", _dev_dir->d_name);
       printf("%s", _buff);
      }
    }

    closedir(_devFP);



  }
