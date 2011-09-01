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

#include "prototypes.h"

#include "beaengine/BeaEngine.h"
#define BEA_ENGINE_STATIC  /* specify the usage of a static version of BeaEngine */
#define BEA_USE_STDCALL    /* specify the usage of a stdcall version of BeaEngine */

extern int disasm_size;	// size of last disassembled instruction

/*
* parse command line/fix argc/argv
* in order to run a binary
*/
int fix_args(int argc,char  **argv){
	int i,parsed=0;
	for (i = 2; i < argc; i++) {
	if(debug_flag)
		printf("argv[%d]=%s\n",i,argv[i]);

		if (!strncmp(argv[i], "-C", 2)) {
			if(verbose_flag)
				printf(" [*] Executing :%s\n", argv[i+1]);
			parsed = 1;
			break;
		}
	}
	if (!parsed) {		// die !
		printf(" [!] Couldn't parse command line\n");
		exit(0);
	} else {
		// fix argv
		int j;
		for (j = i+1; j <= argc; j++) {
			argv[j - i - 1] = argv[j];
		}

		// fix argc
		argc = argc -i -1;
	}
	return argc;
}

/*
* Run a command passed as an argument,
* ptrace it, wait for a crash...
*/
int runcmd(int argc, char **argv, char **envp)
{
	int i, status;
	int child, pid;
	siginfo_t si;

	memset(&si, 0, sizeof(siginfo_t));

	/*
	 * Attempt to parse command line :
	 * where is the proper cmd line starting ?
	 */
	argc=fix_args(argc, argv);

	// display args
	printf(" -->> running: %s with args: ", argv[0]);
	for (i = 0; i < argc; i++) {
		printf("argv[%d]=%s ", i, argv[i]);
	}
	printf("\n");

	/*
	 * We run the given command and expect it
	 * to trigger a SEGFAULT or something..
	 */
	child = fork();
	if (child == 0) {	// child
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		if (execve(argv[0], argv, envp)) {
			perror(" [!!] execve");
			exit(-1);
		}
	} else if (child == -1) {
		perror(" [!!] fork");
		exit(1);
	} else {	// parent
		ptrace(PTRACE_SETOPTIONS, child, 0,
		       PTRACE_O_TRACEFORK |
                        PTRACE_O_TRACEVFORK |
                        PTRACE_O_TRACECLONE |
                        PTRACE_O_TRACEEXEC |
                        PTRACE_O_TRACEVFORKDONE |
                        PTRACE_O_TRACEEXIT);

		while (1) {
			if (waitpid(-1,&status,__WALL) == -1) {
				printf(" [*] traced process exited with status %d\n",WEXITSTATUS(status));
				exit(-1);
			}
			if (WIFSTOPPED(status)) {
				pid = child;	// save child's pid
				if (ptrace(PTRACE_CONT, child, 0, 0) == -1) {
					perror(" [!!] ptrace");
					exit(-1);
				}
				// check return signal/error code
				ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
				if(si.si_signo||si.si_errno||si.si_code){
					printf("[*] Child stopped with signal: %i"
					  " errno: %i code: %i\n", si.si_signo,
					  si.si_errno, si.si_code);
					last_signal=si.si_signo;
					break;
				}
			}
		}
	}
	return pid;
}


/*
* FIXME: most probably the most hugly
* routine in this application atm...
*
*/
int monitor_unaligned(int pid){
	struct	user_regs_struct regz;
	char line[400];

keepexec:
	// Set align flag
	ptrace(PTRACE_GETREGS, pid,NULL, &regz);
	regz.eflags |=0x40000;	// bit 18 in binary
	ptrace(PTRACE_SETREGS, pid,NULL, &regz);

	while(1){
		siginfo_t si;
		memset(&si, 0, sizeof(siginfo_t));

		// continue tracing
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		wait(NULL);

		// display received signals
		ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
		last_signal=si.si_signo;
		if(!si.si_signo){	// Signal 0 ? program ended
//			goto stopdebug;
		} else if(segfault_flag){ 	// If segfault, ignore it
			siginfo_t si;
			memset(&si, 0, sizeof(siginfo_t));

			// void error
			memset(&si, 0, sizeof(siginfo_t));
			ptrace(PTRACE_SETSIGINFO, pid, NULL, &si);

			// disassemble at current ip
			memset(line,0x00,400);
			disassemble(pid,regz.ip,line);

			if(strlen(line)>1){
#ifdef __x86_64__
				printf("0x%016llx: %s\n",regz.rip,line);
#else
				printf("0x%08x: %s\n",(unsigned int)regz.eip,line);
#endif
			}

			// display registers
			display_regs(line,regz);

			// set ip to next instruction
			ptrace(PTRACE_GETREGS, pid,NULL, &regz);
			regz.ip+= disasm_size;
			ptrace(PTRACE_SETREGS, pid,NULL, &regz);

			// void error
			memset(&si, 0, sizeof(siginfo_t));
			ptrace(PTRACE_SETSIGINFO, pid, NULL, &si);

			goto keepexec;
		}

		if(debug_flag){
			printf("signo: %i errno: %i code: %i\n",
			 si.si_signo, si.si_errno,si.si_code);
		}

		zprintf("---------------------------------------------\n");
		ptrace(PTRACE_GETREGS, pid,NULL, &regz);

		// disassemble at current eip
		memset(line,0x00,400);
		disassemble(pid,regz.ip,line);

		if(strlen(line)>1){
#ifdef __x86_64__
			printf("0x%016llx: %s\n",regz.rip,line);
#else
			printf("%08X: %s\n",(unsigned int)regz.eip,line);
#endif
		}

		// display registers
		display_regs(line,regz);

		// void error
		memset(&si, 0, sizeof(siginfo_t));
		ptrace(PTRACE_SETSIGINFO, pid, NULL, &si);

		// remove align flag, single step once, reset align flag and remove trap flag
		ptrace(PTRACE_GETREGS, pid,NULL, &regz);
		regz.eflags ^=0x40000;	// remove Align flag
		regz.eflags |=0x100;	// set Trap flag
		ptrace(PTRACE_SETREGS, pid,NULL, &regz);

		ptrace(PTRACE_CONT, pid, NULL, NULL);	// single step once
		wait(NULL);

		ptrace(PTRACE_GETREGS, pid,NULL, &regz);
		regz.eflags |=0x40000;	// set Align flag
		regz.eflags ^=0x100;	// remove Trap flag
		ptrace(PTRACE_SETREGS, pid,NULL, &regz);

	}
	return 0;
}


