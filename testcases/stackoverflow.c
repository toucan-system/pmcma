#include <stdio.h>

int vuln(char *buf) {
	char buf2[512];
	strcpy(buf2, buf);
	return 0;
}

void main(int argc, void **argv) {

	if(argc > 1)
		vuln(argv[1]);
}
