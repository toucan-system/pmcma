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

#define _FILE_OFFSET_BITS 64	// we want to access files bigger than 2GB
#define _XOPEN_SOURCE 500
#include <unistd.h>

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


#include "banner.h"
#include "archs.h"


#ifdef __x86_64__
#define addr_size unsigned long long int
#else
#define addr_size unsigned int
#endif

/*
* Data structures
*/
#ifdef __x86_64__
// section
struct section {
	unsigned long long int init;	// start address
	unsigned long long int end;	// end address
	int size;	// size
	int perms;	// permissions
	char name[255];	// name
	void *next;	// ptr to next section

	int num;	// section number in memory mapping
	int proba;	// aslr stuff (highest probability of a given mapping)
	int probableval;// aslr stuff (address of most probable mapping)
};

// pointers to data
struct w_to_w_ptr {
	unsigned long long int addr;
	unsigned long long int dst;
	unsigned long long int next;
};

// pointers to rodata
struct w_to_r_ptr {
	unsigned long long int addr;
	unsigned long long int dst;
	unsigned long long int next;
};

// pointers to shared section
struct w_to_s_ptr {
	unsigned long long int addr;
	unsigned long long int dst;
	unsigned long long int next;
};


// function pointers
struct w_to_x_ptr {
	unsigned long long int addr;		// address
	unsigned long long int dst;		// points to this address
	unsigned long long int next;		// ptr to next struct
	int valid;		// points to a X section, disassembly is correct
	char backup[3];
	int trunc;		// can be truncated (id est: mapps to a valid section) ?
	int function_start;	// points to a valid function prologue : push ebp; mov ebp,esp;
	int unaligned;		// is unaligned ?
	int hijack;		// full control flow hijack
	int indirect;		// indirect control flow hijack
	int problem;		// triggers an unspecified error
	int truncsploit;	// exploitation by truncation 
};

struct any_ptr {
	unsigned long long int addr;
	unsigned long long int dst;
	unsigned long long int next;
};

#else
// section
struct section {
	int init;	// start address
	int end;	// end address
	int size;	// size
	int perms;	// permissions
	char name[255];	// name
	void *next;	// ptr to next section

	int num;	// section number in memory mapping
	int proba;	// aslr stuff (highest probability of a given mapping)
	int probableval;// aslr stuff (address of most probable mapping)
};

// pointers to data
struct w_to_w_ptr {
	int addr;
	int dst;
	int next;
};

// pointers to rodata
struct w_to_r_ptr {
	int addr;
	int dst;
	int next;
};

// pointers to shared section
struct w_to_s_ptr {
	int addr;
	int dst;
	int next;
};


// function pointers
struct w_to_x_ptr {
	int addr;		// address
	int dst;		// points to this address
	int next;		// ptr to next struct
	int valid;		// points to a X section, disassembly is correct
	char backup[3];
	int trunc;		// can be truncated (id est: mapps to a valid section) ?
	int function_start;	// points to a valid function prologue : push ebp; mov ebp,esp;
	int unaligned;		// is unaligned ?
	int hijack;		// full control flow hijack
	int indirect;		// indirect control flow hijack
	int problem;		// triggers an unspecified error
	int truncsploit;	// exploitation by truncation 
};

struct any_ptr {
	int addr;
	int dst;
	int next;
};

#endif


#ifdef __x86_64__
struct data_rec{	// recorded syscall data
	int syscall;
	int len;
	char hash[16];
	char buf[100];

	// incoming
	int rax_init;
	int rbx_init;
	int rcx_init;
	int rdx_init;
	int rsi_init;
	int rdi_init;
	int rsp_init;
	int rbp_init;
	int rip_init;

	// results
	int rax;
	char rax_data[100];
	int rbx;
	char rbx_data[100];
	int rcx;
	char rcx_data[100];
	int rdx;
	char rdx_data[100];
	int rsi;
	char rsi_data[100];
	int rdi;
	char rdi_data[100];
	int rbp;
	char rbp_data[100];
	int rsp;
	char rsp_data[100];
	int rip;

	void* next;
};
#else
struct data_rec{	// recorded syscall data
	int syscall;
	int len;
	char hash[16];
	char buf[100];

	// incoming
	int eax_init;
	int ebx_init;
	int ecx_init;
	int edx_init;
	int esi_init;
	int edi_init;
	int esp_init;
	int ebp_init;
	int eip_init;

	// results
	int eax;
	char eax_data[100];
	int ebx;
	char ebx_data[100];
	int ecx;
	char ecx_data[100];
	int edx;
	char edx_data[100];
	int esi;
	char esi_data[100];
	int edi;
	char edi_data[100];
	int ebp;
	char ebp_data[100];
	int esp;
	char esp_data[100];
	int eip;

	void* next;
};
#endif

/*
* function prototypes declarations
*/

int zprintf(const char *format, ...);
int generate_sections(char buff[], unsigned int num);
void getdata(pid_t child, addr_size addr, char *str, int len);
void putdata(pid_t child, addr_size addr, char *str, int len);
int dump_section(int fdin, int fdout, struct section *mysection);
int is_mapped(addr_size addr);
int checktrunc(struct w_to_x_ptr *tmp, int destperm,addr_size inputptr,int direction,int aligned);
int w_to_x_add(addr_size addr, addr_size ptr);
int setbp(int pid, struct w_to_x_ptr *tmp);
int restbp(int pid, struct w_to_x_ptr *tmp);
int init_tracefork(pid_t pid);
int ptr_to_perms(addr_size addr);
int parse_section(int fd, addr_size addr,addr_size end, int size, int perms, char *name);
int find_trunc_targets(int destperm,addr_size inputptr, int aligned);
int kill_group(int pid);
void ptrace_attach(int pid);
void death_timeout(int pid,int runtimeout);
void write_data(int pid, addr_size addr, void *vptr, unsigned int len);
void overwrite_int(int pid,addr_size addr,addr_size value);
int analyze(int pid);
addr_size analyze_registers(char *buff,char *regh,struct user_regs_struct regs);
int aslr_perfs (int pid);
int checkallptrs(int pid);
int check_control_flow(int pid, addr_size value);
int check_uids(int pid);
int crash_analysis(char *asminst);
int disassemble(int pid, addr_size addr, char *line);
int display_possible_fptrs();
int dump_stack(int pid, struct user_regs_struct regz, int fdout);
int generate_dump(int pid);
int inst_analysis(char *buff,struct user_regs_struct regs);
int kill_pid(int pid);
int maxrep(unsigned int i);
int mk_fork_wrapper(pid_t pid);
int mk_fork_wrapper2(pid_t pid);
int mk_fork(pid_t pid);
int monitor_unaligned(int pid);
int print_cmd_line(int pid);
int prompt_user(int pid);
int pwnage_analysis(int pid);
int read_maps(int pid);
int reporting(int pid);
int runcmd(int argc, char **argv, char **envp);
int scan_instruction(char *data);
int scenarios();
int trace_to_segfault(int pid);
int validate_ptrs(int pid);
int walk_stack(int pid, struct user_regs_struct regz);
int w_to_r_add(addr_size addr, addr_size ptr);
int w_to_s_add(addr_size addr, addr_size ptr);
int w_to_w_add(addr_size addr, addr_size ptr);
int parse_w_sections(int pid);
int check_install();
int checksec(int pid);
int reportsec();
int exec_cmd(char *command,int pid);
int display_regs(char *line, struct user_regs_struct regz);
int mk_mmap(int pid);
int mk_setpgid(int pid);
int record_syscalls(int pid);
int analyse_leaks(int pid);
int get_syscall(pid_t pid);
int check_leak(int pid, int value);
FILE* exec_cmd_stdout(char *command,int pid);
int mk_mmap_exec(int pid);
int grepcount(char *pattern, FILE *input);
int ptr_to_aslrval(addr_size addr);
int memleak_analysis(int pid);
int detect_next_crash(int pid);
int validate_struct_ptrs(int pid);
int exploit(int pid);
int ptr_to_aslr(addr_size addr);

/* runtime configuration flags */
extern int segfault_flag;
extern int single_ptr;
extern int fptr_flag;
extern int leakshowsyscalls_flag;
extern int leak_flag;		 	
extern int unaligned_flag;
extern int interactive_flag;
extern int verbose_flag;
extern int dump_flag;
extern int strict_mode;
extern FILE *reportz;
extern int last_signal;

 
// binary/RCE properties
int PIE_flag;
int stackcookies_flag;
int FORTIFY_flag;
int PARTIAL_RELRO_flag;
int FULL_RELRO_flag;
int execstack_flag;
int cpp_flag;
int socket_flag;
int server_flag;
int debug_flag;
int uid, euid, saved_uid, fsuid;
int gid, egid, saved_gid, fsgid;
int stackexec_flag;
int heapexec_flag;
int bssexec_flag;
int dataexec_flag;
int stackexecmprot_flag;
int heapexecmprot_flag;
int bssexecmprot_flag;
int dataexecmprot_flag;

// Other globals
int read_op;
int write_op;
char reg1h[10];
char reg2h[10];
addr_size reg1val;
addr_size reg2val;
int num_operands;
int deref1;
int deref2;
int num_frames;
int stack_smash;
addr_size start_eip;
addr_size second_eip;
int crash_loop;
int exploit_flag;

addr_size testvalue2;
addr_size saved_last_eip;
#define REPORTDIR "./"

