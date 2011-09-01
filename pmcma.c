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

extern char *sig_desc[];


/* runtime configuration flags */
int segfault_flag=0;
int single_ptr=0;
int fptr_flag=0;		 	
int leak_flag=0;
int leakshowsyscalls_flag=0;
int unaligned_flag=0;
int interactive_flag=0;
int verbose_flag=0;
int version_flag=0;
int dump_flag=0;
int cmd_flag=0;
int last_signal=0;
int debug_flag=0;
int x_flag=0;
int exploit_flag=0;
int skip_death=0;

// default values, can be changed at runtime:
int test_value=0xf1f2f3f4;	// this is the value we'll use to overwrite function ptrs
int runtimeout=2;
int num_samples=100;
int strict_mode=1;

FILE* reportz;	// report file

int usage(char **argv){

	printf("Usage: %s [OPTIONS]\n"
	"OPTIONS:\n"
	"--help (-h):			Display this help\n"
	"--version (-V):		Display version\n"
	"--pid=<pid> (-p):		pid to trace\n"
	"--verbose (-v):		Be verbose\n"
	"--debug   (-d):		Debug mode\n"
	"--dump    (-D):		Dump sections to disk\n"
	"--segfault (-s):		start tracing after segfault\n"
	"--leak (-l):			search memory leaks to defeat ASLR using a write operation\n"
	"--leak-showsyscalls (-X):	show syscalls performed when looking for mem leaks\n"
	"--fptr (-f):			only search for function ptrs when analysing invalid writes (faster)\n"
	"--unaligned (-u):		search for instructions using unaligned reads/writes\n"
	"--interactive (-i):		prompt user (default is: auto mode)\n"
	"--canari (-c):			use given value when trying to overwrite function ptrs\n"
	"--timeout (-t):		timeout when running forked() children. Default: 2s\n"
	"--relaxed (-r):		use relaxed mode when searching for function ptrs\n"
	"--assume-X (-x):		assume that everything mapped is executable\n"
	"--num-samples (-n):		take this number of samples when checking ASLR\n"
	"--single-ptr=<0xaddress> (-S):	analyse only this address\n"
	"-C <cmd arg1 arg2...>	:	run the given command instead of following a pid\n\n",argv[0]);
	return 0;
}

int main(int argc, char *argv[], char *envp[]) {

	int c=0, pid=0;

	/*
	* Command line options parsing
	*/
	if(argc < 2){
		usage(argv);
		exit(-1);
	}
	while (1) {
		int option_index = 0;
		const struct option long_options[] =
		    { 	{"help", 0, 0, 'h'},
			{"version",0,0, 'V'},
			{"pid", 2, 0, 'p'},
			{"segfault", 0, 0, 's'},
			{"interactive", 0, 0, 'i'},
			{"unaligned", 0, 0, 'u'},
			{"leak", 0, 0, 'l'},
			{"leak-showsyscalls", 0, 0, 'X'},
			{"fptr", 0, 0, 'f'},
			{"single-ptr", 2, 0, 'S'},
			{"verbose", 0, 0, 'v'},
			{"debug", 0, 0, 'd'},
			{"dump", 0, 0, 'D'},
			{"cmd", 2, 0, 'C'},
			{"canari", 2, 0, 'c'},
			{"timeout", 2, 0, 't'},
			{"relaxed", 2, 0, 'r'},
			{"num-samples", 2,0, 'n'},
			{"exploit",2,0,'x'},
			{0, 0, 0, 0}
		    };

		char c2 = getopt_long(argc, argv, "XVfldDhisuvp:S:C:c:t:r:xn:", long_options,
				&option_index);
		if (c2 == -1)
			break;

		switch (c2) {
		case 'h':
			usage(argv);
			exit(-1);
			break;

		case 's':
			segfault_flag=1;
			break;

		case 'V':
			version_flag=1;
			break;

		case 'i':
			interactive_flag=1;
			break;

		case 'l':
			leak_flag=1;
			break;

		case 'X':
			leakshowsyscalls_flag=1;
			break;


		case 'f':
			fptr_flag=1;
			break;

		case 'u':
			unaligned_flag=1;
			break;

		case 'v':
			verbose_flag=1;
			break;

		case 'd':
			debug_flag=1;
			break;

		case 'D':
			dump_flag=1;
			break;

		case 'r':
			strict_mode=0;
			break;

//		case 'x':
//			x_flag=1;
//			break;

		case 'x':
			exploit_flag=1;
			break;

		case 'p':
			if(optarg != 0) {
				pid=atoi(optarg);
			} else {
				usage(argv);
				exit(-1);
			}
			break;

		case 'n':
			if(optarg != 0) {
				num_samples=atoi(optarg);
			} else {
				usage(argv);
				exit(-1);
			}
			break;

		case 't':
			if(optarg != 0) {
				runtimeout=atoi(optarg);
			} else {
				usage(argv);
				exit(-1);
			}
			break;

		case 'c':
			if(optarg != 0) {
				test_value=strtoul(optarg+2,(char ** __restrict__)optarg+12,16);
			} else {
				usage(argv);
				exit(-1);
			}
			break;

		case 'S':
			if(optarg != 0) {
				single_ptr=strtoul(optarg+2,(char ** __restrict__)optarg+12,16);
			} else {
				usage(argv);
				exit(-1);
			}
			break;

		case 'C':	// we're given a command, ignore the rest
			cmd_flag=1;
			goto cmdparsedone;
		default:
			fprintf(stderr, "[!!] unknown option : '%c'\n", c);
			exit(-2);
		}
	}
cmdparsedone:

	/*
	* small integrity check
	*/
	if(pid&&cmd_flag){
		printf(" [!!] Options --pid and --cmd are incompatible\n");
		exit(-1);
	}

	if(version_flag){
		printf("PMCMA Version: %s\n",VERSION);
		exit(0);
	}

	/*
	* check if we were installed properly
	*/
	check_install();

	if(!pid){
		/*
		* We were not given a pid : run application
		* given at command line using execve
		*/
		pid=runcmd(argc,argv,envp);
	}

	/* 
	* start debugging by attaching to a running pid
	*/
	if((pid)&&(!cmd_flag)){	
		ptrace_attach(pid);
	}

	/*
	* If segfault mode is on, wait for a segfault
	*/
	if(segfault_flag){
		trace_to_segfault(pid);
	}

	/*
	* Dump a maximum of information
	* about the debugged process
	*/
	reporting(pid);

	/*
	* Check only for unaligned read/writes
	*/
	if(unaligned_flag){
		monitor_unaligned(pid);
	}

	/*
	* main routine
	*/
	pwnage_analysis(pid);
	return 0;
}

