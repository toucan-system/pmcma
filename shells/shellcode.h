#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

// prints a string "passed" if it worked
char shellcode[]="\xeb\x19\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb2"
		"\x07\x59\xb3\x01\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd"
		"\x80\xe8\xe2\xff\xff\xff\x70\x61\x73\x73\x65\x64\x0a";


