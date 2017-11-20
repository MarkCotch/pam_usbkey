#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "foblib.h"

int main() {

	char buff[256];
	char *res;
	res=findKeyFOB(buff);
	if (! res) exit (1) ;
	printf ("res:\t%lu\t: %s\n", res, res);
	printf ("buff:\t%lu\t: %s\n", buff, buff);
	struct stat filePerms;
	stat (res, &filePerms);
	printf("0x%o\n", filePerms.st_mode);

}
