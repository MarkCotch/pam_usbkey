#include <stdio.h>
#include <string.h>

main () {
  char _char=0;
  char _charArray100[100]={0};
  char *_ptrArray=_charArray100;
  int _int=0;
  int _intArray100[100]={0};

  printf("_char size: %d \n", sizeof(_char));
  printf("_charArray100 size: %d \n", sizeof(_charArray100));
  printf("*_ptrArray size: %d\n", sizeof(*_ptrArray));
  printf("_ptrArray size: %d\n", sizeof(_ptrArray));
  printf("_int size: %d \n", sizeof(_int));
  printf("_intArray100 size: %d \n", sizeof(_intArray100));
}
