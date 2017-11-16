#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

main () {
  int rval;
  rval = system ("grep \"$(ssh-keygen -P PassPhrase -y -f %s 2>&1 )\" /root/.ssh/authorized_keys");
  printf("rval= %d", rval);
}
