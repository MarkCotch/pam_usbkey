#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

main () {
  int rval;
  FILE *cmdFP;
  char buff[2048];

  /* rval = system ("grep \"$(ssh-keygen -P PassPhrase -y -f %s 2>&1 )\" /root/.ssh/authorized_keys");
  printf("rval= %d \n", rval); */
  cmdFP = popen("grep \"$(ssh-keygen -P PassPhrase -y -f /dev/vdb1 2>&1 )\" /root/.ssh/authorized_keys | cut -d' ' -f3", "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }
   while (fgets(path, sizeof(path)-1, cmdFP) != NULL) {
    printf("%s", path);
  }
  pclose (cmdFP);
}
