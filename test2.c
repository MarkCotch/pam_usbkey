/*

  The file is for testing and experimentation.

*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <dirent.h>

int main( int argc, char **argv ) {
  const char *_sys_dev_block="/sys/dev/block";
  DIR *_devFP;
  FILE *_blockDev;
  _devFP=opendir(_sys_dev_block);
  struct dirent *_blockDir;

  while ( _blockDir=readdir(_devFP) ) {
    if (_blockDir->d_name[0] != '1' )
      printf ( "%s\n", _blockDir->d_name );
  }
}
