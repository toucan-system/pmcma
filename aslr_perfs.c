/*
*
*          Post memory corruption memory analyzer
*
*
*
*   Copyright 2011 Toucan System SARL
*
*   Licensed under the Apache License, Version 2.0 (the "License");
*   you may not use this file except in compliance with the License.
*   You may obtain a copy of the License at
*
*       http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*   See the License for the specific language governing permissions and
*   limitations under the License.
*
*
*/

#include <errno.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <sys/user.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>
#include <sys/user.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <math.h>
#include <math.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

#include "prototypes.h"

extern int num_samples;
extern int nsections;
struct section *zfirst_aslr;
extern struct section *zfirst;
extern int myargc;
extern char **myargv;
extern FILE *stdin;

addr_size *aslrtab;

#ifdef __x86_64__
#include <sys/syscall.h>
	int allowed_syscalls[]={__NR_read,__NR_open,__NR_close,__NR_execve,__NR_access,__NR_brk,__NR_munmap,__NR_mprotect,__NR_mmap,__NR_fstat,__NR_set_thread_area,__NR_arch_prctl};
#else
	int allowed_syscalls[]={3,5,6,11,33,45,91,125,192,197,243};
#endif

/*
Those syscalls are used during execve() and dynamic loading : 
					 x86	x86-64
	read                             3 	0
	open                             5 	2
	close                            6 	3
	execve                           11 	59
	access                           33 	21
	brk                              45 	12
	munmap                           91 	11
	mprotect                         125 	10
	mmap2                            192 	9 (mmap)
	fstat64                          197 	5 (fstat)
	set_thread_area                  243	205
	arch_prctl			  -     158
*/




/*
* bubble sorting routine
*/
void bubbleSort(addr_size numbers[], int array_size){
 	int i, j;
	addr_size temp;
 
	for (i = (array_size - 1); i > 0; i--){
		for (j = 1; j <= i; j++){
			if (numbers[j-1] > numbers[j]){
				temp = numbers[j-1];
				numbers[j-1] = numbers[j];
				numbers[j] = temp;
			}
		}
	}
}

/*
* Get syscall
*/
int get_syscall(pid_t pid) {
#ifdef __x86_64__
    return (int)ptrace(PTRACE_PEEKUSER, pid, 4*ORIG_RAX, 0); 
#else
    return (int)ptrace(PTRACE_PEEKUSER, pid, 4*ORIG_EAX, 0); 
#endif
}

int aslr_init(int numsections){
	aslrtab=(addr_size *)malloc((numsections)*(num_samples)*2*sizeof(addr_size));
	return 0;
}

int aslr_addval(unsigned int i,unsigned int sample,addr_size addr){
	aslrtab[i*num_samples+sample]=addr;
	return 0;
}

int aslr_sumup(unsigned int i){
	bubbleSort((addr_size*)aslrtab+i*num_samples,num_samples);
	maxrep(i);

	return 0;
}

int maxrep(unsigned int i){
	struct section *tmpsection;
	unsigned int j;
	unsigned int count=1;
	addr_size prev=0;
	addr_size mostval=0;
	unsigned int maxcount=0;

	for(j=i*num_samples;j<(i+1)*num_samples;j++){
		if(aslrtab[j]==prev){
			count++;
		}else{
			prev=aslrtab[j];
			count=1;
		}

		if(count>maxcount){
			maxcount=count;
			mostval=aslrtab[j];
		}
	}

	// find matching section in liked list
	tmpsection = zfirst;	// carefull, not zfirst_aslr
	while (tmpsection->next != 0x00) {
		if((addr_size)tmpsection->num==i)
			break;
		tmpsection = tmpsection->next;
	}

	// flag its probability
	tmpsection->proba=maxcount;
	tmpsection->probableval=mostval;

	// display results
#ifdef __x86_64__
	zprintf("[section:%03d] %s\n  most probable address:0x%016llx, proba%s%03d/%d\n",
		i,tmpsection->name,mostval,(maxcount == (unsigned int)num_samples) ? "=" : "<",maxcount,num_samples);
#else
	zprintf("[section:%03d] %s\n  most probable address:0x%08x, proba%s%03d/%d\n",
		i,tmpsection->name,mostval,(maxcount == (unsigned int)num_samples) ? "=" : "<",maxcount,num_samples);
#endif
	return 0;
}

int aslr_clean(){
	struct section *oldsection;
	struct section *tmpsection;

	// free main table
	free(aslrtab);
	// free all the data
	tmpsection = zfirst_aslr;
	while (tmpsection->next != 0x00) {
		oldsection=tmpsection;
		tmpsection = tmpsection->next;
		free(oldsection);
	}
	free(tmpsection);
	return 0;
}


int save_section(FILE *dataf,struct section *section){
	if(section->num%nsections==1){
		fprintf(dataf,"\n%u",(unsigned int)section->init);
	}else{
		fprintf(dataf," %u",(unsigned int)section->init);
	}

	return 0;
}


/*
* Check if a received syscall is still part of the loading/dynamic loading
*/
int still_loading(int s){
	unsigned int i;
	for(i=0;i<sizeof(allowed_syscalls);i++){
		if(s==allowed_syscalls[i])
			return 1;
	}
	return 0;
}


/*
* Run a command passed as an argument,
* stop when execve + dynamic loading is done
* record mapping to further study ASLR
*/
int run_aslr_tests(int argc, char *argv, char **envp)
{
	int status,s;
	pid_t child;
	siginfo_t si;

	memset(&si, 0, sizeof(siginfo_t));

	/*
	 * We run the given command, wait for the
	 * mapping to be done, and read the map
	 */
	if ((child = fork()) < 0) {
		perror("fork:");
		exit(-1);
	} else if (!child) {	// child 

		FILE *f=fopen("/dev/zero","r");	// just in case it starts with a read...
		stdin=f;

		ptrace(PTRACE_TRACEME, 0, 0, 0);

		// drop privileges (if any)
//		setgid(gid);
//		setuid(uid);

		execle((char*)argv, (char*)argv, NULL,envp);
		perror("execve:");
		exit(-1);
	}

	while (1) {
		// Wait for an event
		while (waitpid(child,&status,0) < 0) {
			if (errno == ECHILD) {
				printf(" [!!] Child exited\n");
				exit(0);
			} else if (errno == EINTR) {
				continue;
			} else {
				perror("wait:");
				exit(-1);
			}
		}

		s=get_syscall(child);
		if(still_loading(s)){
			ptrace(PTRACE_SYSCALL, child, 0, 0);
//		} else if (s == -1){
//			usleep(200);
		//	ptrace(PTRACE_SYSCALL, child, 0, 0);
//			goto done_tracing;

		}else{
			goto done_tracing;
		}
	}
done_tracing:
	// read mapping
	read_maps(child);	
	//kill child
	kill_pid(child);
	waitpid(child,&status,0);
	return 0;

}


/*
* Run ASLR tests
*/
int aslr_perfs (int pid){

	int i,nsections_bak,myargc;
	char myargv[1024];
	char lpath[1024];

	// hack: needs API change
	struct section *zfirst_back;
	zfirst_back=zfirst;
	zfirst=0;
	nsections_bak=nsections;

	myargc=1;

	memset(myargv,0x00,1024);
	sprintf(lpath,"/proc/%d/exe",pid);
	readlink(lpath,myargv,1024);

	zprintf("\n--[ Performing ASLR tests:\n");
	for(i=0;i<num_samples;i++){
		run_aslr_tests(myargc,myargv,0x00);	
	}

	// restore zfirst
	zfirst_aslr=zfirst;
	zfirst=zfirst_back;
	aslr_init(nsections_bak);

	// study each section mapped
	for(i=1;i<=nsections_bak;i++){
		int sample=0;
		struct section *tmpsection = zfirst_aslr;
		while (tmpsection != 0x00) {
			if(tmpsection->num==i)
				aslr_addval(i,sample++,tmpsection->init);

			tmpsection = tmpsection->next;
		}
		aslr_sumup(i);
	}

	aslr_clean();
	nsections=nsections_bak;
	return 0;
}


