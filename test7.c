#include <stdio.h>

main (){
	int loop;
	for (loop=0 ; loop < 255 ; loop++) {
		printf ("%d : %c \n", loop, loop);
	}
}
