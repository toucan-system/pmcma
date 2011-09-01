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
#include "analyze.h"

#include <errno.h>

extern int num_samples;
extern int test_value;
extern int runtimeout;

// internal globals
int process_to_kill=0;
int sighandler_initialized=0;

extern struct w_to_x_ptr *w_to_x_first;
extern struct w_to_w_ptr *w_to_w_first;
extern int w_to_w_counter;
extern int w_to_r_counter;

extern int num_frames;

extern int skip_death;


/*
* Security properties checking routine,
* loosely based on Tobias Klein's checksec.sh
* (http://www.trapkit.de/tools/checksec.html)
*
* The way were are doing it IS better for some
* of the commands (works on (s)stripped binaries).
*
*/
int checksec(int pid){
	FILE *target;

	// check for PIE executables
	target=exec_cmd_stdout("readelf -h /proc/%d/exe 2>/dev/null",pid);	
	PIE_flag=!grepcount("Type:[[:space:]]*EXEC", target);
	pclose(target);	

	// check for stack cookies
	target=exec_cmd_stdout("strings /proc/%d/exe 2>/dev/null",pid);
	stackcookies_flag=grepcount("__stack_chk_fail", target);
	pclose(target);

	// check for FORTIFY_SOURCE hardened functions
	target=exec_cmd_stdout("strings /proc/%d/exe 2>/dev/null",pid);
	FORTIFY_flag=grepcount("__[a-z]*_chk", target);
	pclose(target);

	// check for Partial RELRO
	target=exec_cmd_stdout("readelf -l /proc/%d/exe 2>/dev/null",pid);
	PARTIAL_RELRO_flag=grepcount("GNU_RELRO", target);
	pclose(target);

	// check for Full RELRO
	target=exec_cmd_stdout("readelf -d /proc/%d/exe 2>/dev/null",pid);
	FULL_RELRO_flag=grepcount("BIND_NOW", target);
	pclose(target);

	// check for Executable stack
	target=exec_cmd_stdout("execstack -q /proc/%d/exe 2>/dev/null",pid);
	FULL_RELRO_flag=grepcount("^X", target);
	pclose(target);

	// check if linked against stdc++ library (means we'll find function ptrs...)
	target=exec_cmd_stdout("ldd /proc/%d/exe 2>/dev/null",pid);
	cpp_flag=grepcount("libstdc++", target);
	pclose(target);

	// bind/accept/connect : uses sockets
	target=exec_cmd_stdout("nm -D /proc/%d/exe 2>/dev/null",pid);
	cpp_flag=grepcount(" bind | accept | connect ", target);
	pclose(target);

	// accept() -> server
	target=exec_cmd_stdout("nm -D /proc/%d/exe 2>/dev/null",pid);
	cpp_flag=grepcount(" accept ", target);
	pclose(target);

	return 0;
}


/*
* Check a few NX properties from
* the kernel. Much like a reduced
* version of paxtest.
*/
int kernel_props(){
	//int result;
	FILE *target;
	chdir("../shells/");

	zprintf("\n--[ Kernel properties:\n");

	// exectable stack ?
	target=exec_cmd_stdout("./sh_stack 2>/dev/null",0);
	stackexec_flag=grepcount("passed", target);
	pclose(target);

	// exectable heap ?
	target=exec_cmd_stdout("./sh_heap 2>/dev/null",0);
	heapexec_flag=grepcount("passed", target);

	pclose(target);

	// exectable bss ?
	target=exec_cmd_stdout("./sh_bss 2>/dev/null",0);
	bssexec_flag=grepcount("passed", target);
	pclose(target);

	// exectable data ?
	target=exec_cmd_stdout("./sh_data 2>/dev/null",0);
	dataexec_flag=grepcount("passed", target);
	pclose(target);

	// exectable stack (after mprotect) ?
	target=exec_cmd_stdout("./sh_stack_mprotect 2>/dev/null",0);
	stackexecmprot_flag=grepcount("passed", target);
	pclose(target);

	// exectable heap (after mprotect) ?
	target=exec_cmd_stdout("./sh_heap_mprotect 2>/dev/null",0);
	heapexecmprot_flag=grepcount("passed", target);
	pclose(target);

	// exectable bss (after mprotect) ?
	target=exec_cmd_stdout("./sh_bss_mprotect 2>/dev/null",0);
	bssexecmprot_flag=grepcount("passed", target);
	pclose(target);

	// exectable data (after mprotect) ?
	target=exec_cmd_stdout("./sh_data_mprotect 2>/dev/null",0);
	dataexecmprot_flag=grepcount("passed", target);
	pclose(target);

	return 0;

}

/*
* Display the results of checksec()
*/
int reportsec(){
	zprintf("\n--[ Binary properties:\n");
	zprintf(" <*> PIE file: \t\t\t%s\n",(PIE_flag == 1) ? "yes" : "no");
	zprintf(" <*> Stack Cookies: \t\t%s\n",(stackcookies_flag == 1) ? "yes" : "no");
	zprintf(" <*> FORTIFY_SOURCE: \t\t%s\n",(FORTIFY_flag == 1) ? "yes" : "no");
	zprintf(" <*> Partial RELRO: \t\t%s\n",(PARTIAL_RELRO_flag == 1) ? "yes" : "no");
	zprintf(" <*> Full RELRO: \t\t%s\n",(FULL_RELRO_flag == 1) ? "yes" : "no");
	zprintf(" <*> Executable stack: \t\t%s\n",(execstack_flag == 1) ? "yes" : "no");
	zprintf(" <*> C++ binary: \t\t%s\n",(cpp_flag == 1) ? "yes" : "no");
	zprintf(" <*> Uses sockets: \t\t%s\n",(socket_flag == 1) ? "yes" : "no");
	zprintf(" <*> Acts as server: \t\t%s (unreliable)\n",(server_flag == 1) ? "yes" : "no");

	return 0;
}

/*
* Display results of kernel tests:
*/
int kprops(){
	zprintf(" <*> Executable stack: \t\t\t%s\n",(stackexec_flag == 1) ? "yes" : "no");
	zprintf(" <*> Executable heap: \t\t\t%s\n",(heapexec_flag == 1) ? "yes" : "no");
	zprintf(" <*> Executable bss: \t\t\t%s\n",(bssexec_flag == 1) ? "yes" : "no");
	zprintf(" <*> Executable data: \t\t\t%s\n",(dataexec_flag == 1) ? "yes" : "no");
	zprintf(" <*> Executable stack (mprotect): \t%s\n",(stackexecmprot_flag == 1) ? "yes" : "no");
	zprintf(" <*> Executable heap (mprotect): \t%s\n",(heapexecmprot_flag == 1) ? "yes" : "no");
	zprintf(" <*> Executable bss (mprotect): \t%s\n",(bssexecmprot_flag == 1) ? "yes" : "no");
	zprintf(" <*> Executable data (mprotect): \t%s\n",(dataexecmprot_flag == 1) ? "yes" : "no");
	return 0;
}

int sig_to_desc(int sig){
	unsigned int i;
	for(i=0;i<sizeof(sig_numbers)/sizeof(int);i++){
		if(sig_numbers[i]==sig){
			return i;
		}
	}
	return -1;
}

int analyze(int pid){
	struct	user_regs_struct regz;
	char asminst[400];
	int fdstack;

	// print banner
	zprintf(BANNER);

	zprintf("\n--[ Reading binary mapping:\n\n");

	read_maps(pid);

	// Dump each section to disk
	if(dump_flag){
		zprintf("\n--[ Dumping sections to disk:\n\n");
		generate_dump(pid);
	}
	// Get arguments or die !
	if(ptrace(PTRACE_GETREGS , pid , NULL , &regz) < 0) exit(-1);
	memset(asminst,0x00,400);
	disassemble(pid,regz.ip,asminst);

	// print pid
	zprintf("\n\n--[ Pid:\n%d\n\n",pid);

	// print command line
	print_cmd_line(pid);

	// print context informations
	memset(asminst,0x00,400);

	disassemble(pid,regz.ip,asminst);
#ifdef __x86_64__
	zprintf("--[ Pid:\n%d\n\n"
		"--[ Stopped at:\n%s\n\n"
		"--[ Registers:\n"
		"rax=0x%016llx\n"
		"rbx=0x%016llx\n"
		"rcx=0x%016llx\n"
		"rdx=0x%016llx\n"
		"rsi=0x%016llx\n"
		"rdi=0x%016llx\n"
		"rsp=0x%016llx\n"
		"rbp=0x%016llx\n"
		"rip=0x%016llx\n\n--[ Walking stack:\n"
		,pid,asminst,regz.rax, regz.rbx, 
		regz.rcx, regz.rdx, regz.rsi,
		regz.rdi, regz.rsp, regz.rbp,
		regz.rip);

	// save rip
	start_eip=regz.rip;
#else
	zprintf("--[ Pid:\n%d\n\n"
		"--[ Stopped at:\n%s\n\n"
		"--[ Registers:\n"
		"eax=0x%08x\n"
		"ebx=0x%08x\n"
		"ecx=0x%08x\n"
		"edx=0x%08x\n"
		"esi=0x%08x\n"
		"edi=0x%08x\n"
		"esp=0x%08x\n"
		"ebp=0x%08x\n"
		"eip=0x%08x\n\n--[ Walking stack:\n"
		,pid,asminst,regz.eax, regz.ebx, 
		regz.ecx, regz.edx, regz.esi,
		regz.edi, regz.esp, regz.ebp,
		regz.eip);

	// save eip
	start_eip=regz.eip;
#endif

	// dump stack to disk
	fdstack=open(REPORTDIR"/stack",O_RDWR|O_CREAT|O_TRUNC,0755);
	dump_stack(pid,regz,fdstack);

	// walk stack back
	num_frames=walk_stack(pid,regz);

	if(num_frames){
		zprintf(" --> Stack was likely not corrupted (%d valid frames found)\n",num_frames);
	}else{
		zprintf(" --> Stack was probably corrupted (no valid frame found)\n");
	}

	// register/instruction analysis
	inst_analysis(asminst,regz);

	// crash analysis
	crash_analysis(asminst);

	// check security properties:
	checksec(pid);
	reportsec();

	// check for setuid/setgid
	check_uids(pid);

	// study aslr
	aslr_perfs(pid);

	// study kernel properties
	kernel_props();

	// show results
	kprops();

	// make educated exploitation scenarios
	scenarios();

	// find pointers (to any mapped section) in +W sections
	parse_w_sections(pid);

	// verify function pointers that actually point to a valid instruction
	checkallptrs(pid);

	return 0;
}

/*
* Parse the linked list of possible function pointers,
* overwrite them, see the result...
*/
int validate_ptrs(int pid){

	struct w_to_x_ptr *tmp4;
	int counter = 0;
	int counter_ind =0;
	int newpid,ret;
	char line[400];
	struct	user_regs_struct regz;

	zprintf("\n--[ Validating function pointers (%s):\n",strict_mode ? "strict mode" : "relaxed mode");
	tmp4 = w_to_x_first;

	while (tmp4 != 0) {

		if ((tmp4->valid)&&(tmp4->function_start||(!strict_mode))) {

			// make fork()
			newpid=mk_fork_wrapper(pid);
			if(debug_flag)
				printf(" ** Attempting to hijack function pointer "
#ifdef __x86_64__
				"at %016llx with new pid=%d\n",tmp4->addr,newpid);
#else
				"at %08x with new pid=%d\n",tmp4->addr,newpid);
#endif
			// Overwrite function ptr with test value
			overwrite_int(newpid,tmp4->addr,test_value);

			// Run and verify if control flow is
			// actually passed at this address
			ret=check_control_flow(newpid,test_value);

			if(ret != -1){
				switch(ret){
					case 0:
#ifdef __x86_64__
						zprintf("\n <*> Dereferenced function ptr at 0x%016llx (full control flow hijack)\n",tmp4->addr);
						zprintf("     0x%016llx --> 0x%016llx %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
#else
						zprintf("\n <*> Dereferenced function ptr at 0x%08x (full control flow hijack)\n",tmp4->addr);
						zprintf("     0x%08x --> 0x%08x %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
#endif

						tmp4->hijack=1;
						counter++;
						break;
					case 1:
#ifdef __x86_64__
						zprintf("\n <-> Triggered an indirect control flow bug when writing at 0x%016llx\n     (ret value=0x%016llx is unmapped)\n",tmp4->addr,saved_last_eip);
						zprintf("     0x%016llx --> 0x%016llx %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
#else
						zprintf("\n <-> Triggered an indirect control flow bug when writing at 0x%08x\n     (ret value=0x%08x is unmapped)\n",tmp4->addr,saved_last_eip);
						zprintf("     0x%08x --> 0x%08x %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
#endif
						tmp4->indirect=1;
						counter_ind++;
						break;
					default:		// so we got a segfault, without executing an unmapped location. Multi-core cpus trigger this most of the time

						// verify we are not segfaulting at original address because of a loop
						if(saved_last_eip==start_eip){
							goto not_good;
						}
						// disassemble at destination
						memset(line,0x00,400);
						disassemble(newpid,saved_last_eip,line);

						// does this look like a control flow instruction (call/j.*) ?
						if(((line[0]&0xff) == 0x6a)||(!strncmp(line,"call",4))){
#ifdef __x86_64__
							zprintf("\n <*> Triggered a segmentation fault when writing at 0x%016llx\n     (segfault at: 0x%016llx, full control flow hijack)\n",
#else
							zprintf("\n <*> Triggered a segmentation fault when writing at 0x%08x\n     (segfault at: 0x%08x, full control flow hijack)\n",
#endif
								tmp4->addr,saved_last_eip);
							tmp4->hijack=1;
							counter++;
						} else {
							// ignore if not in verbose mode
							if(!verbose_flag){
								goto not_good;
							}
#ifdef __x86_64__
							zprintf("\n <-> Triggered an indirect bug without control flow hijack\n     when writing at 0x%016llx\n     (ret value=0x%016llx)\n",
#else
							zprintf("\n <-> Triggered an indirect bug without control flow hijack\n     when writing at 0x%08x\n     (ret value=0x%08x)\n",
#endif
								tmp4->addr,saved_last_eip);
						}
						// display disasm 
						zprintf("     %s\n",line);
#ifdef __x86_64__
						zprintf("     0x%016llx --> 0x%016llx %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
#else
						zprintf("     0x%08x --> 0x%08x %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
#endif
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
not_good:
						break;
				}
			}else{

				if(verbose_flag)
					printf("."); // show visual progression of the analysis
			}
			// kill process anyways
			kill_pid(newpid);
		}
		tmp4 = (struct w_to_x_ptr *)tmp4->next;
	}

	zprintf("\n --> total : %d validated function pointers\n            "
		"(and found %d additional control flow errors)\n",
		 counter,counter_ind);

	return 0;
}





/*
* Parse the linked lists for qny writable data,
* overwrite one address at a time, see the result...
*/
int validate_all_w(int pid,int aslr){

	struct w_to_x_ptr *tmp4;
	int counter = 0;
	int counter_ind =0;
	int newpid,ret;
	char line[400];
	struct	user_regs_struct regz;

	zprintf("\n--[ Overwriting any writable address in %s:\n",aslr ? "any section (hardcore/costly mode)" : "non randomised sections");
	tmp4 = w_to_x_first;

	while (tmp4 != 0) {

		if ((tmp4->valid)&&(tmp4->function_start||(!strict_mode))) {

			// make fork()
			newpid=mk_fork_wrapper(pid);
			if(debug_flag)
				printf(" ** Attempting to hijack function pointer "
#ifdef __x86_64__
				"at %016llx with new pid=%d\n",tmp4->addr,newpid);
#else
				"at %08x with new pid=%d\n",tmp4->addr,newpid);
#endif
			// Overwrite function ptr with test value
			overwrite_int(newpid,tmp4->addr,test_value);

			// Run and verify if control flow is
			// actually passed at this address
			ret=check_control_flow(newpid,test_value);

			if(ret != -1){
				switch(ret){
					case 0:
#ifdef __x86_64__
						zprintf("\n <*> Dereferenced function ptr at 0x%016llx (full control flow hijack)\n",tmp4->addr);
						zprintf("     0x%016llx --> 0x%016llx %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
#else
						zprintf("\n <*> Dereferenced function ptr at 0x%08x (full control flow hijack)\n",tmp4->addr);
						zprintf("     0x%08x --> 0x%08x %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
#endif
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
						tmp4->hijack=1;
						counter++;
						break;
					case 1:
#ifdef __x86_64__
						zprintf("\n <-> Triggered an indirect control flow bug when writing at 0x%016llx\n     (ret value=0x%016llx is unmapped)\n",tmp4->addr,saved_last_eip);
						zprintf("     0x%016llx --> 0x%016llx %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
#else
						zprintf("\n <-> Triggered an indirect control flow bug when writing at 0x%08x\n     (ret value=0x%08x is unmapped)\n",tmp4->addr,saved_last_eip);
						zprintf("     0x%08x --> 0x%08x %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
#endif
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
						tmp4->indirect=1;
						counter_ind++;
						break;
					default:		// so we got a segfault, without executing an unmapped location. Multi-core cpus trigger this most of the time

						// verify we are not segfaulting at original address because of a loop
						if(saved_last_eip==start_eip){
							goto not_good;
						}
						// disassemble at destination
						memset(line,0x00,400);
						disassemble(newpid,saved_last_eip,line);

						// does this look like a control flow instruction (call/j.*) ?
						if(((line[0]&0xff)== 0x6a)||(!strncmp(line,"call",4))){
#ifdef __x86_64__
							zprintf("\n <*> Triggered a segmentation fault when writing at 0x%016llx\n     (segfault at: 0x%016llx, full control flow hijack)\n",
#else
							zprintf("\n <*> Triggered a segmentation fault when writing at 0x%08x\n     (segfault at: 0x%08x, full control flow hijack)\n",
#endif
								tmp4->addr,saved_last_eip);
							tmp4->hijack=1;
							counter++;
						} else {
							// ignore if not in verbose mode
							if(!verbose_flag){
								goto not_good;
							}
#ifdef __x86_64__
							zprintf("\n <-> Triggered an indirect bug without control flow hijack\n     when writing at 0x%016llx\n     (ret value=0x%08x)\n",
#else
							zprintf("\n <-> Triggered an indirect bug without control flow hijack\n     when writing at 0x%08x\n     (ret value=0x%08x)\n",
#endif
								tmp4->addr,saved_last_eip);
						}
						// display disasm 
						zprintf("     %s\n",line);
#ifdef __x86_64__
						zprintf("     0x%016llx --> 0x%016llx %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
#else
						zprintf("     0x%08x --> 0x%08x %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
#endif
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
not_good:
						break;
				}
			}else{

				if(verbose_flag)
					printf("."); // show visual progression of the analysis
			}
			// kill process anyways
			kill_pid(newpid);
		}
		tmp4 = (struct w_to_x_ptr *)tmp4->next;
	}

	zprintf("\n --> total : %d validated function pointers\n            "
		"(and found %d additional control flow errors)\n",
		 counter,counter_ind);

	return 0;
}


/*
* Check if a given integer is of form 0xABABXXXX
*
*/
int is_struct_fptr(int ptr){
	return (((ptr >> 24) & 0xff) == ((ptr >> 16) & 0xff)) ? 1 : 0;	// thx msuiche :))
}

/*
* We are looking for pointers to structures containing a function pointer...
*/
int validate_struct_ptrs(int pid){

	struct w_to_w_ptr *tmp4;
	int counter = 0;
	int counter_ind =0;
	int newpid,ret;
	int new_mapping;
	char line[400];

	zprintf("\n--[ Searching pointers to datastructures with function pointers\n");

	zprintf("\n ** Pointers to +W sections: %d\n",w_to_w_counter);
	zprintf("\n ** Pointers to +R sections: %d\n",w_to_r_counter);

	tmp4 = w_to_w_first;
	if(tmp4==0){
		return -1;
	}

	while (tmp4 != 0) {
		// make fork()
		newpid=mk_fork_wrapper(pid);

		// create new zone with canari mapping
		new_mapping=mk_mmap(newpid);

		// Overwrite function ptr with test value (new mapping)
		overwrite_int(newpid,tmp4->addr,new_mapping);

		// Run and verify if control flow is
		// actually transfered to a pointer inside the mapping...
		ret=check_control_flow(newpid,test_value);
		if((ret != -1)&&(is_struct_fptr(saved_last_eip))){	// verify the executed instruction is looking like a canari value... // note: this may have false negatives.
				switch(ret){
					case 0:
					case 1:
						zprintf("\n <*> Dereferenced a function pointer inside a structure when writing at 0x%08x\n     (ret value=0x%08x)",tmp4->addr,saved_last_eip);
						zprintf(" // repeatability:%d/%d\n",ptr_to_aslr(tmp4->addr),num_samples);
						counter++;
					default:		// so we got a segfault, without executing an unmapped location. Multi-core cpus trigger this most of the time

						// verify we are not segfaulting at original address because of a loop
						if(saved_last_eip==start_eip){
							goto not_good2;
						}
						// disassemble at destination
						memset(line,0x00,400);
						disassemble(newpid,saved_last_eip,line);

						// does this look like a control flow instruction (call/j.*) ?
						if(((line[0]&0xff)== 0x6a)||(!strncmp(line,"call",4))){
#ifdef __x86_64__
						zprintf("\n <*> Dereferenced a function pointer inside a structure when writing at 0x%016llx\n     (ret value=0x%016llx)",tmp4->addr,saved_last_eip);
#else
						zprintf("\n <*> Dereferenced a function pointer inside a structure when writing at 0x%08x\n     (ret value=0x%08x)",tmp4->addr,saved_last_eip);
#endif
							counter++;
						}
						// display disasm 
						zprintf("     %s\n",line);
						zprintf("     0x%08x --> 0x%08x %s // repeatability:%d/%d\n", tmp4->addr, tmp4->dst,
						       (tmp4->addr % 4) ? "(unalined)" : "",ptr_to_aslr(tmp4->addr),num_samples);
not_good2:
					break;
			}
		}else{

			if(verbose_flag)
				printf("."); // show visual progression of the analysis
		}

		// kill debugged process anyway...
		kill_pid(newpid);
		tmp4 = (void *)tmp4->next;
	}

	zprintf("\n --> total : %d function pointers identified inside structures\n", counter);

	return 0;
}


/*
* Overwrite one function ptr
*/
void overwrite_int(int pid,addr_size addr,addr_size value){
	write_data(pid,addr,&value,sizeof(addr_size));
}

int check_control_flow(int pid, addr_size value){

	int status;
	addr_size r;
	struct	user_regs_struct regs;
	siginfo_t si;

	// clear signals
	memset(&si, 0, sizeof(siginfo_t));
	if(ptrace(PTRACE_SETSIGINFO, pid, NULL, &si)){
//		perror(" [!!] ptrace (PTRACE_SETSIGINFO)");
		return -1;
	}

	// schedule death of debugged program after timeout
	if(!skip_death)
		death_timeout(pid,runtimeout);

	// continue execution
	if(ptrace(PTRACE_CONT, pid, NULL, NULL)){
		perror(" [!!] ptrace (PTRACE_CONT)");
		return -1;
	}

	// wait for an event
	waitpid(pid,&status,0);

	// we got back, remove timeout
	if(!skip_death)
		alarm(0);

	if (errno == ECHILD) {	// Child exited, #failed
		if(debug_flag)
			printf(" ** process exited\n");
		return -1;
	}

	// check signals
	if(ptrace(PTRACE_GETSIGINFO, pid, NULL, &si)){
//		perror(" [!!] ptrace (PTRACE_GETSIGINFO)");
		return -1;
	}
	if(debug_flag)
		printf("signo: %i errno: %i code: %i\n", si.si_signo, si.si_errno,
	            si.si_code);

	if(si.si_signo!=11){	// Other signal, #failed
		return -1;
	}

	// get registers
	if(ptrace(PTRACE_GETREGS, pid,NULL, &regs)){
		perror(" [!!] ptrace (PTRACE_GETREGS)");
		return -1;
	}

	// save last ip
	saved_last_eip=regs.ip;

	// check value of eip
	if(regs.ip==value){
		if(verbose_flag)
			printf(" -->> Direct control flow hijack\n");
		return 0;	// success !!
	}

	r= regs.ip;

	if(!is_mapped(r)){
		if(verbose_flag)
			printf(" -->> Indirect control flow hijack (unexpected return value: 0x%p)\n", (void*)r);
		return 1;
	}

	if(verbose_flag)
		printf(" -->> Indirect bug ? (unexpected return value: 0x%p)\n",(void*)r);
	return 2;	// not sure
}



/*
* SIGALARM handler : kill debugged process
*/
void timeout_handler(int signo, siginfo_t *info, ucontext_t *context){
	kill_pid(process_to_kill);
}

/*
* Routine to initialize the
* SIGALRM signal handler
*/
void set_timeout_handler(){

	struct sigaction sa;	
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = (void *)timeout_handler;
	sigaction(SIGALRM, &sa, NULL);

	sighandler_initialized=1;
}

/*
* Send a SIGKILL to debugged process after
* timeout (to avoid deadloops...)
*
* Note: signal handler can only handle one
* process, don't try to multithread...
*
*/
void death_timeout(int pid,int runtimeout){

	if(!sighandler_initialized)
	set_timeout_handler();

	process_to_kill=pid;

	alarm(runtimeout);
}

/*
* Kill a given pid. Insist...
*/
int kill_pid(int pid){

	siginfo_t si;

	if(!pid){
		return 0;
	}

	if(debug_flag)
		printf("killing:%d\n",pid);

	// attempt to kill normally
	kill(pid,SIGTERM);
	kill(pid,SIGKILL);

	// clear signals
	memset(&si, 0, sizeof(siginfo_t));
	ptrace(PTRACE_SETSIGINFO, pid, NULL, &si);

	// die fucker, FTW !!
	ptrace(PTRACE_KILL,pid,0,0);
	ptrace(PTRACE_CONT, pid, 0, 0);
	kill(pid,SIGTERM);
	ptrace(PTRACE_DETACH, pid, 0, 0);
	kill(pid,SIGTERM);
	kill(pid,SIGKILL);

	return 0;
}

/*
* Kill a process group
*/
int kill_group(int pid){

	if(!pid){
		return 0;
	}

	// attempt to kill normally
	kill(-pid,SIGTERM);
	kill(-pid,SIGKILL);
	kill(-pid,SIGCONT);
	kill(-pid,SIGTERM);
	kill(-pid,SIGKILL);

	return 0;
}

/*
* Parse the instruction the application stopped at.
*/
int inst_analysis(char *buff,struct user_regs_struct regs){

	char tmp[100];
	char *lim;

	scan_instruction(buff);

	zprintf("\n--[ Instruction analysis:\n");

	if(write_op){
		zprintf(" --> write operation\n");
	}else if(read_op){
		zprintf(" --> read operation\n");
	}else{
		zprintf(" --> not a write operation\n");	// probable...
	}

	memset(reg1h,0x00,10);
	memset(reg2h,0x00,10);

	lim=strchr(buff,0x2c); // search ","
	if(lim){
		num_operands=2;
		// search first (output) register
		memset(tmp,0x00,100);
		strncpy(tmp,buff,(int)(lim-buff));
		reg1val=analyze_registers(tmp,reg1h,regs);

		if(strchr(tmp,0x5b)){ // "["
			deref1=1;
		}
		// search second (input) register
		memset(tmp,0x00,100);
		strcpy(tmp,lim);
		reg2val=analyze_registers(tmp,reg2h,regs);

		if(strchr(tmp,0x5b)){ // "["
			deref2=1;
		}

	}else{
		num_operands=1;
		// there is at most one operand
		reg1val=analyze_registers(buff,reg1h,regs);

		if(strchr(buff,0x5b)){ // "["
			deref1=1;
		}

		if(!strlen(reg1h)){
			num_operands=0;
		}
	}
	if(num_operands==2){
#ifdef __x86_64__
		zprintf(" --> (2 operands) reg1:%s=0x%016llx,reg2:%s=0x%016llx\n",
			reg1h,reg1val,reg2h,reg2val);
#else
		zprintf(" --> (2 operands) reg1:%s=0x%08x,reg2:%s=0x%08x\n",
			reg1h,reg1val,reg2h,reg2val);
#endif
	}else if(num_operands==1){
#ifdef __x86_64__
		zprintf(" --> (1 operand) reg1:%s=0x%016llx\n",
			reg1h,reg1val);
#else
		zprintf(" --> (1 operand) reg1:%s=0x%08x\n",
			reg1h,reg1val);
#endif
	}else{
		zprintf(" --> instruction takes no operands\n");
	}

	if(deref1){
		zprintf(" --> the first operand is dereferenced\n");
	}
	if(deref2){
		zprintf(" --> the second operand is dereferenced\n");
	}

	return 0;
}

addr_size analyze_registers(char *buff,char *regh,struct user_regs_struct regs){
	long regval;

#ifdef __x86_64__
	// 64b
	if (strstr(buff, "rax")){
		strcpy(regh,"rax");
		regval=regs.rax;
	}
	if (strstr(buff, "rbx")){
		strcpy(regh,"rbx");
		regval=regs.rbx;
	}
	if (strstr(buff, "rcx")){
		strcpy(regh,"rcx");
		regval=regs.rcx;
	}
	if (strstr(buff, "rdx")){
		strcpy(regh,"rdx");
		regval=regs.rdx;
	}
	if (strstr(buff, "rsi")){
		strcpy(regh,"rsi");
		regval=regs.rsi;
	}
	if (strstr(buff, "rdi")){
		strcpy(regh,"rdi");
		regval=regs.rdi;
	}
	if (strstr(buff, "rsp")){
		strcpy(regh,"rsp");
		regval=regs.rsp;
	}
	if (strstr(buff, "rbp")){
		strcpy(regh,"rbp");
		regval=regs.rbp;
	}

	if (strstr(buff, "r8")){
		strcpy(regh,"r8");
		regval=regs.r8;
	}
	if (strstr(buff, "r9")){
		strcpy(regh,"r9");
		regval=regs.r9;
	}
	if (strstr(buff, "r10")){
		strcpy(regh,"r10");
		regval=regs.r10;
	}
	if (strstr(buff, "r11")){
		strcpy(regh,"r11");
		regval=regs.r11;
	}
	if (strstr(buff, "r12")){
		strcpy(regh,"r12");
		regval=regs.r12;
	}
	if (strstr(buff, "r13")){
		strcpy(regh,"r13");
		regval=regs.r13;
	}
	if (strstr(buff, "r14")){
		strcpy(regh,"r14");
		regval=regs.r14;
	}
	if (strstr(buff, "r15")){
		strcpy(regh,"r15");
		regval=regs.r15;
	}

	if(strlen(regh))
		return regval ;


	// 32b
	if (strstr(buff, "eax")){
		strcpy(regh,"eax");
		regval=regs.rax&0xffffffff;
	}
	if (strstr(buff, "ebx")){
		strcpy(regh,"ebx");
		regval=regs.rbx&0xffffffff;
	}
	if (strstr(buff, "ecx")){
		strcpy(regh,"ecx");
		regval=regs.rcx&0xffffffff;
	}
	if (strstr(buff, "edx")){
		strcpy(regh,"edx");
		regval=regs.rdx&0xffffffff;
	}
	if (strstr(buff, "esi")){
		strcpy(regh,"esi");
		regval=regs.rsi&0xffffffff;
	}
	if (strstr(buff, "edi")){
		strcpy(regh,"edi");
		regval=regs.rdi&0xffffffff;
	}
	if (strstr(buff, "esp")){
		strcpy(regh,"esp");
		regval=regs.rsp&0xffffffff;
	}
	if (strstr(buff, "ebp")){
		strcpy(regh,"ebp");
		regval=regs.rbp&0xffffffff;
	}

	if(strlen(regh))
		return regval ;

	// 16b
	if (strstr(buff, "ax")){
		strcpy(regh,"ax");
		regval=regs.rax&0x0000ffff;
	}
	if (strstr(buff, "bx")){
		strcpy(regh,"bx");
		regval=regs.rbx&0x0000ffff;
	}
	if (strstr(buff, "cx")){
		strcpy(regh,"cx");
		regval=regs.rcx&0x0000ffff;
	}
	if (strstr(buff, "dx")){
		strcpy(regh,"dx");
		regval=regs.rdx&0x0000ffff;
	}

	// 8b low
	if (strstr(buff, "al")){
		strcpy(regh,"al");
		regval=regs.rax&0x000000ff;
	}
	if (strstr(buff, "bl")){
		strcpy(regh,"bl");
		regval=regs.rbx&0x000000ff;
	}
	if (strstr(buff, "cl")){
		strcpy(regh,"cl");
		regval=regs.rcx&0x000000ff;
	}
	if (strstr(buff, "dl")){
		strcpy(regh,"dl");
		regval=regs.rdx&0x000000ff;
	}

	// 8b high
	if (strstr(buff, "ah")){
		strcpy(regh,"ah");
		regval=regs.rax&0x0000ff00;
	}
	if (strstr(buff, "bh")){
		strcpy(regh,"bh");
		regval=regs.rbx&0x0000ff00;
	}
	if (strstr(buff, "ch")){
		strcpy(regh,"ch");
		regval=regs.rcx&0x0000ff00;
	}
	if (strstr(buff, "dh")){
		strcpy(regh,"dh");
		regval=regs.rdx&0x0000ff00;
	}


#else

	// 32b
	if (strstr(buff, "eax")){
		strcpy(regh,"eax");
		regval=regs.eax;
	}
	if (strstr(buff, "ebx")){
		strcpy(regh,"ebx");
		regval=regs.ebx;
	}
	if (strstr(buff, "ecx")){
		strcpy(regh,"ecx");
		regval=regs.ecx;
	}
	if (strstr(buff, "edx")){
		strcpy(regh,"edx");
		regval=regs.edx;
	}
	if (strstr(buff, "esi")){
		strcpy(regh,"esi");
		regval=regs.esi;
	}
	if (strstr(buff, "edi")){
		strcpy(regh,"edi");
		regval=regs.edi;
	}
	if (strstr(buff, "esp")){
		strcpy(regh,"esp");
		regval=regs.esp;
	}
	if (strstr(buff, "ebp")){
		strcpy(regh,"ebp");
		regval=regs.ebp;
	}

	if(strlen(regh))
		return regval ;

	// 16b
	if (strstr(buff, "ax")){
		strcpy(regh,"ax");
		regval=regs.eax&0x0000ffff;
	}
	if (strstr(buff, "bx")){
		strcpy(regh,"bx");
		regval=regs.ebx&0x0000ffff;
	}
	if (strstr(buff, "cx")){
		strcpy(regh,"cx");
		regval=regs.ecx&0x0000ffff;
	}
	if (strstr(buff, "dx")){
		strcpy(regh,"dx");
		regval=regs.edx&0x0000ffff;
	}

	// 8b low
	if (strstr(buff, "al")){
		strcpy(regh,"al");
		regval=regs.eax&0x000000ff;
	}
	if (strstr(buff, "bl")){
		strcpy(regh,"bl");
		regval=regs.ebx&0x000000ff;
	}
	if (strstr(buff, "cl")){
		strcpy(regh,"cl");
		regval=regs.ecx&0x000000ff;
	}
	if (strstr(buff, "dl")){
		strcpy(regh,"dl");
		regval=regs.edx&0x000000ff;
	}

	// 8b high
	if (strstr(buff, "ah")){
		strcpy(regh,"ah");
		regval=regs.eax&0x0000ff00;
	}
	if (strstr(buff, "bh")){
		strcpy(regh,"bh");
		regval=regs.ebx&0x0000ff00;
	}
	if (strstr(buff, "ch")){
		strcpy(regh,"ch");
		regval=regs.ecx&0x0000ff00;
	}
	if (strstr(buff, "dh")){
		strcpy(regh,"dh");
		regval=regs.edx&0x0000ff00;
	}
#endif
	return regval;
}

/*
* Give a verbose description of the bug in human
* language.
*/
int crash_analysis(char *asminst){
	unsigned int v;
	int maj;
	zprintf("\n--[ Crash analysis:\n");

	stack_smash=0;

	if(!last_signal){
		zprintf(" ** The application didn't crash\n");
		return 0;
	}

	zprintf(" ** The application received a %s signal (number %d), while performing \n ",
		sig_desc[sig_to_desc(last_signal)],last_signal);

	if(write_op){
		zprintf("a write instruction");
	}else if(read_op){
		zprintf("a read instruction");
	}else{
		zprintf("an instruction");
	}

	zprintf(" (%s) with %d operand%s, of which %s\n is being dereferenced.\n",asminst,num_operands,
		(num_operands==1) ? "" : "s", deref1 ? "the first one" : deref2 ? "the second one" : "none");

	if(write_op||deref1||deref2||read_op){
		zprintf(" ** The pointer dereference is failing because");

		if(write_op&&strlen(reg1h)){
			zprintf(" the register %s,\n worthing 0x%08x at this time, ",reg1h,reg1val);
			v=reg1val;
			maj=1;
		}else if (read_op&&strlen(reg2h)){
			zprintf(" the register %s,\n worthing 0x%08x at this time, ",reg2h,reg2val);
			v=reg2val;
			maj=2;
		}else if(deref1&&strlen(reg1h)){
			zprintf(" the register %s,\n worthing 0x%08x at this time, ",reg1h,reg1val);
			v=reg1val;
			maj=1;
		}else if(deref2&&strlen(reg2h)){
			zprintf(" the register %s,\n worthing 0x%08x at this time, ",reg2h,reg2val);
			v=reg2val;
			maj=2;
		}else if(num_frames<2){
			zprintf(" the stack appears to be corrupted\n");
			stack_smash=1;
		}else{
			zprintf(" of a non obvious reason.\n");
			goto skipderef;
		}

		if(!is_mapped(v)){
			zprintf(" is pointing to unmapped memory.\n");
		}else{
			zprintf(" is pointing to a memory section\n with permissions\" "
				" uncompatible with this operation.\n");	// TODO: add section name, perms
		}

	if(read_op||write_op||deref1||deref2){
	zprintf(" ** The impact of this bug is potentially to %s ", write_op ? "modify the control flow\n"
		" of the application to execute arbitrary code.\n" :  "perform a controled read\n"
		" operation, leading either to direct information leakage\n (of an interresting value, or"
		" more generally of the mapping of the binary),\n or indirectly to an other memory corruption bug.\n");
	}else if(stack_smash){
		zprintf(" ** The impact of this bug is potentially to execute arbitrary code\n");
		goto skipderef;
	}

	if(!is_mapped(v)&&is_mapped(v+10)){
		zprintf(" ** It is worth noticing that 0x%08x is only a few bytes before a mapped section\n It may be the sign of an underflow computation.\n");
	}else if (!is_mapped(v)&&is_mapped(v-10)){
		zprintf(" ** It is worth noticing that 0x%08x is only a few bytes after a mapped section\n It may be the sign of an overflow computation.\n");
	}else if(v > 0xf0000000){
		zprintf(" ** It is worth noticing that the value 0x%08x is very big :\n it may be the result of an earlier integer overflow.\n",v);
	}else if(v == 0x0){
		zprintf(" ** It is worth noticing that 0x00000000 is normally never mapped().\n If the value of this register cannot be changed, the"
		" bug is not exploitable.\n");
	}

	if((maj==1)&&(strlen(reg2h))){
		if(!reg2val){
			zprintf(" ** It is also worth mention that if register %s can only worth 0x00000000\n"
			" exploitation will be harder (but not necessarily impossible, due\n to possible unaligned pointer truncations, or"
			" by overwriting\n other data and triggering an other memory corruption indirectly).\n",reg2h);
		}
	}

	if(write_op)
		testvalue2=v;	// we'll use this value when performing truncations etc.

skipderef:	
	(0);	// fuck gcc
	}


	return 0;
}

/*
* Make exploitation scenarios out of the gathered informations
*/
int scenarios(){
	return 0;
}


int detect_next_crash(int pid){
	int status;
	struct	user_regs_struct regs;
	siginfo_t si;
	int test_pid;

	zprintf("\n--[ Loop detection:\n");

	test_pid=mk_fork_wrapper(pid);

	// schedule death of debugged program after timeout
	death_timeout(test_pid,2*runtimeout);

	// continue execution
	if(ptrace(PTRACE_CONT, test_pid, NULL, NULL)){
		perror(" [!!] ptrace (PTRACE_CONT)");
		return -1;
	}

	// wait for an event
	waitpid(test_pid,&status,0);

	// we got back, remove timeout
	alarm(0);

	if (errno == ECHILD) {	// Child exited, #failed
		if(debug_flag)
			printf(" ** process exited\n");
		return -1;
	}


	// check signals
	if(ptrace(PTRACE_GETSIGINFO, test_pid, NULL, &si)){	// no signal
		crash_loop=0;
		second_eip=0;
		goto print_res;
	}
	if(debug_flag)
		printf("signo: %i errno: %i code: %i\n", si.si_signo, si.si_errno,
	            si.si_code);

	// get registers
	if(ptrace(PTRACE_GETREGS, test_pid,NULL, &regs)){
		perror(" [!!] ptrace (PTRACE_GETREGS)");
		return -1;
	}

	second_eip=regs.ip;

	if(start_eip==second_eip){	// do we crash in a loop?
		crash_loop=1;
	}

	if(verbose_flag)
		zprintf("<*> first stop: 0x%08x,  last stop: 0x%08x\n",start_eip,second_eip);
print_res:
	zprintf("<*> crash in a loop : %s\n",crash_loop ? "yes" : "no");

	kill_pid(test_pid);
	return 0;
}

