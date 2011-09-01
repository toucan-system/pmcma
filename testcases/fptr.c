#include <stdio.h>
#include <stdlib.h>

void (*f)(void);

void foobar(){
	printf("I've been called :)\n");
}

int main (int argc, char **argv){

	printf("pid=%d\n",getpid());
	f=&foobar;
	sleep(10);

	printf("survived...\ndereferencing fptr...");

	f();

	return 0;
}

