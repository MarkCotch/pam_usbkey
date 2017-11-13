/*

  The file is for testing and experimentation.

*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>

struct passwd *userID;


main( int argc, char **argv )
  {

    userID=getpwnam(argv[1]);
    printf ("%s \n", userID->pw_dir);



  }
