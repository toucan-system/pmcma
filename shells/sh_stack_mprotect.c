#include "shellcode.h"

static void handler(int sig, siginfo_t *si, void *unused){
	exit(-1);
}

int main (int argc, char **argv){
	char buff[50];
	void (*f)(void);

	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = handler;
	if (sigaction(SIGSEGV, &sa, NULL) == -1)
		perror("sigaction");

	memset(buff,0x00,50);
	strcpy(buff,shellcode);
	mprotect((void *)((unsigned int)buff&0xfffff000),4096,PROT_READ|PROT_EXEC|PROT_WRITE);
	f = (void*)buff;
	f();
	return 0;
}

