#include "shellcode.h"

char buff[50];

static void handler(int sig, siginfo_t *si, void *unused){
	exit(-1);
}

int main (int argc, char **argv){
	void (*f)(void);
	memset(buff,0x00,50);
	strcpy(buff,shellcode);
	f = (void*)buff;

	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = handler;
	if (sigaction(SIGSEGV, &sa, NULL) == -1)
		perror("sigaction");

	f();
	return 0;
}

