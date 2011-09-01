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

#define _XOPEN_SOURCE 500
#define _FILE_OFFSET_BITS 64
#include <math.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>

#include "prototypes.h"
#include "syscalls.h"

#include "beaengine/BeaEngine.h"
#define BEA_ENGINE_STATIC	/* specify the usage of a static version of BeaEngine */
#define BEA_USE_STDCALL		/* specify the usage of a stdcall version of BeaEngine */
#define MAX_FAIL_TIMES 1000	/* max number of times to attemp a mk_fork() before desisting */

#define MAX_DATA_SIZE 100

#ifndef __x86_64__
#include "shellcode_x86_linux.h"
#else
#include "shellcode_x86_64_linux.h"
#endif

extern int skip_death;
extern int test_value;

extern int runtimeout;

int base_stack;

double crc64(char *seq, char *res);

int nrec=0;


char backup_buff[200];	// backup bytes when patching with stub shellcodes

// first pointers for linked lists
struct w_to_x_ptr *w_to_x_first = 0;	// pointers to executable sections
struct w_to_w_ptr *w_to_w_first = 0;	// pointers to data sections
struct w_to_r_ptr *w_to_r_first = 0;	// pointers to rodata sections
struct w_to_s_ptr *w_to_s_first = 0;	// pointers to shared sections

int w_to_w_counter=0;
int w_to_r_counter=0;
int w_to_s_counter=0;

// Other globals
struct section *zfirst = 0;
struct data_rec *recfirst=0;

int nsections=0;
int tracing_forks_flag=0;
int first_fork=1;

//////////////////////////////////////// CODE ////////////////////////////////////////////////

/*
* Simple hexdump routine
*/
int hexdump(char *a, int n)
{
	int i, j;
	for (j = 0; j < n; j += 16) {
		for (i = j; i < j + 16; i++) {
			if (i < n) {
				printf("%02x ", a[i] & 255);
			} else {
				printf("   ");
			}
		}
		printf("   ");
		for (i = j; i < j + 16; i++) {
			if (i < n)
				putchar(32 <= (a[i] & 127)&& (a[i] & 127) < 127 ? a[i] & 127 : '.');
			else
				putchar(' ');
		}
		putchar('\n');
	}
	return 0;
}


int match(const char *string, char *pattern)
{
	int status;
	regex_t re;

	// Compile regexp
	if (regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0) {		
        	return(0); // There was an error compiling regexp
	}
	status = regexec(&re, string, (size_t) 0, NULL, 0); // We don't care about the positions of the matches
    	regfree(&re);
	if (status != 0) {
        	return(0); // No match found
    	}

    	return(1); // Match found
}


int grepcount(char *pattern, FILE *input) {
	char line[1000];
       	int found = 0;
	
	if (input != NULL) {
	   rewind(input);
	   while ( fgets ( line, sizeof line, input ) != NULL ) {
           	if (match(line, pattern) > 0) {
           	    found++;
           	}
	   }
	}

	return found;
}

void ptrace_attach(int pid)
{
	if ((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0) {
		perror(" [!!] ptrace_attach");
		exit(-1);
	}
	waitpid(pid, NULL, WUNTRACED);
}

void ptrace_detach(int pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		perror(" [!!] ptrace_detach");
		exit(-1);
	}
}

void read_data(int pid, unsigned long addr, void *vptr, unsigned int len)
{
	unsigned int i, count;
	long word;
	unsigned long *ptr = (unsigned long *)vptr;
	count = i = 0;

	while (count < len) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
		count += 4;
		ptr[i++] = word;
	}
}

void write_data(int pid, addr_size addr, void *vptr, unsigned int len)
{
	unsigned int i, count;
	long word;
	i = count = 0;

	while (count < len) {
		memcpy(&word, vptr + count, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
		count += 4;
	}
}

void getdata(pid_t child, addr_size addr, char *str, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;
	i = 0;
	j = len / sizeof(long);
	laddr = str;
	while (i < j) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
		memcpy(laddr, data.chars, sizeof(long));
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
		memcpy(laddr, data.chars, j);
	}
	str[len] = '\0';
}

void putdata(pid_t child, addr_size addr, char *str, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;
	i = 0;
	j = len / sizeof(long);
	laddr = str;
	while (i < j) {
		memcpy(data.chars, laddr, sizeof(long));
		ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0) {
		memcpy(data.chars, laddr, j);
		ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
	}
}


/*
* read /proc/pid/map
*/
int read_maps(int pid)
{
	char mpath[255];
	FILE *fmaps;
	char line[1000];
#ifdef __x86_64__
	unsigned long long int initz, endz, size;
#else
	unsigned long int initz, endz, size;
#endif
	char *name;
	unsigned int counter=1;
	struct section *zptr;
	unsigned int perms, t;
	int delta;

	// path to maps file
	sprintf(mpath, "/proc/%d/maps", pid);
	fmaps = fopen(mpath, "r");

	if (fmaps == NULL) {
		perror("[!!] Error reading maps file");
		exit(1);	   
	}

	while ( fgets ( line, sizeof line, fmaps ) != NULL ) {
#ifdef __x86_64__

		// we first need to check if the possible address is a 32 or 64 one		
		initz = strtoul(line, NULL, 16);
		endz = strtoul(strchr(line, '-')+1, NULL, 16);		
		size = endz - initz;

		delta=strchr(line, ' ')-line;
#else
		delta=18;
		endz = strtoull(line + 9, NULL, 16);
		initz = strtoull(line + 0, NULL, 16);
		size = endz - initz;
#endif

		// find permissions
		perms = 0;
		for (t = 0; t < 4; t++) {
			switch (line[t + delta]) {
			case 'r':
				perms += 2;	/*printf(" read "); */
				break;
			case 'w':
				perms += 4;	/*printf(" write "); */
				break;
			case 'x':
				perms += 1;	/*printf(" execute "); */
				break;
			case 'p':		/*printf(" private "); */
				break;
			case 's':
				perms += 8;	/*printf(" shared "); */
				break;
			}
		}

		// find name
		strtok(line, " ");
		for (t=0;t<5;t++) {
			name = strtok(NULL, " ");			
		}
		// Remove leading spaces
		while(*name != '\0' && isspace(*name))
		{
			++name;
		}
		// Remove trailing newline
		name[strlen(name) - 1] = '\0';
		
		// Omit vsyscall as pread fails for the last address
		if (!strncmp("[vsyscall]", name,10)) 
			continue;

		// add to linked list
		zptr = (struct section *)malloc(sizeof(struct section));		
		memset(zptr, 0x00, sizeof(struct section));
		zptr->init = initz;
		zptr->end = endz;
		zptr->size = size;
		zptr->perms = perms;
		zptr->num=counter++;
		strcpy(zptr->name, name);

		if (zfirst == 0x00) {	// we are first
			zfirst = zptr;

		} else {	// append
			struct section *tmpsection = zfirst;
			while (tmpsection->next != 0x00) {
				tmpsection = tmpsection->next;
			}
			tmpsection->next = zptr;

		}
	}

	nsections=counter-1;
	return 0;
}


/*
* dump each memory section to disk
*/
int generate_dump(int pid)
{
	char dev[50];
	int fdin,fdout;	
	struct section *tmpsection;

	memset(dev,0x00,50);
	sprintf(dev,"/proc/%d/mem",pid);

	fdin=open64(dev,O_RDONLY|O_LARGEFILE);
	fdout=open64(REPORTDIR"/memdump",O_RDWR|O_TRUNC|O_CREAT|O_LARGEFILE,0755);

	tmpsection = zfirst;
	while (tmpsection != 0x00) {
		dump_section(fdin, fdout, tmpsection);
		tmpsection = tmpsection->next;
	}
	return 0;
}

/*
* dump one section to disk
*/
int dump_section(int fdin, int fdout, struct section *mysection)
{
	int num, ret_num;
	char *buffer;
	char fname[200];
	int f2;

	if(verbose_flag){
		printf("** dumping (%s %p-%p) of size %ld\n",
		 mysection->name, (void *)mysection->init, (void *)mysection->end,(long)mysection->size);
	}

	buffer = (char *)malloc(mysection->size);
	num=pread64(fdin,buffer,mysection->size,
		(unsigned long int)mysection->init);
	if (num <= 0) {
		perror(" [!!] pread64");
		printf(" [!!] section dumping (%s %p-%p) (%u bytes) failed!\n",
		 mysection->name, (void *)mysection->init, (void *)mysection->end, mysection->size);
		return -1;
	}

	ret_num=pwrite64(fdout,buffer, num,
		(unsigned long int)mysection->init);
	if (ret_num <= 0) {
		perror(" [!!] pwrite64");
		printf(" [!!] section dumping (%s %p-%p) (%u/%u bytes) failed!\n",
		 mysection->name, (void *)mysection->init, (void *)mysection->end, num, mysection->size);
		return -1;
	}

	// also dump section in a separate file
	memset(fname, 0x00, 200);
	sprintf(fname, REPORTDIR "/%p-%p.dump", (void *)mysection->init,
		(void *)mysection->end);
	f2 = open64(fname, O_RDWR | O_TRUNC | O_CREAT | O_LARGEFILE, 0755);
	if(f2 <0){
		perror(" [!!] open");
		exit(-2);
	}
	write(f2, buffer, ret_num);
	close(f2);
	free(buffer);
	return 0;
}

/*
* dump stack to disk
*/
int dump_stack(int pid, struct user_regs_struct regz, int fdout)
{
	int err = 0;
	unsigned int addr;
	unsigned int min;
	unsigned int max = 0xc0000000;
	long word;
	int w;
	unsigned int count = 0;

	if (regz.sp < regz.bp) {
		min = regz.bp;
	} else {
		min = regz.bp;
	}

	base_stack=min;

	addr = min;
	while (count < max - min) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
		if (word == -1) {
			if (err > 10) {
				return 0;
			}
			err++;
		}

		w = write(fdout, &word, sizeof(word));
		if (w <= 0) {
			perror(" [!!] write");
		}
		count += 4;
	}
	return 0;
}

/*
* walk stack from current ebp/esp to higher mem addresses
* this will fail if stack has been corrupted
*/
int walk_stack(int pid, struct user_regs_struct regz){
	int err = 0;
#ifdef __x86_64__
	unsigned long long int addr;
	unsigned long long int bp, sp;
	unsigned long long int word;
	char tmp[16];
#else
	unsigned int addr;
	unsigned int bp, sp;
	long word;
#endif
	int i=0;
	struct w_to_w_ptr *tmp1;
	struct w_to_x_ptr *tmp3;

	sp = regz.sp;
	bp = regz.bp;

	while (is_mapped(bp)) {
		addr = bp;

		// get saved bp
#ifdef __x86_64__
		memset(tmp,0x00,16);
		getdata(pid,addr,tmp,16);
//hexdump(tmp,16);
		word=strtoul(tmp,0x00,16);
//printf("word: 0x%016llx bp: 0x%016llx sp: 0x%016llx\n",word,bp,sp);
#else
		word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
#endif
		if (word == -1) {
			if (err > 10) {
				return 0;
			}
			err++;
		}
		bp = word;

		if (!is_mapped(bp)) {
			return i;
		}

		if(verbose_flag)
#ifdef __x86_64__
			zprintf("          [[ Frame %d ]]\nSaved bp at "
				"0x%16llx --> 0x%16llx\n",i,addr, (int)word);
#else
			zprintf("          [[ Frame %d ]]\nSaved bp at "
				"0x%08x --> 0x%08x\n",i,addr, (int)word);
#endif
		i++;

		// get saved ip
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + 4, NULL);
		if (word == -1) {
			if (err > 10) {
				return i;
			}
			err++;
		}

		if (!is_mapped(word)) {
			return i;
		}

		if(verbose_flag)
#ifdef __x86_64__
			zprintf("Saved ip at 0x%016llx --> 0x%016llx\n"
			"--------------------------------------\n",
			 addr + 4, (int)word);
#else
			zprintf("Saved ip at 0x%08x --> 0x%08x\n"
			"--------------------------------------\n",
			 addr + 4, (int)word);
#endif
		// save in linked lists...

		// save ebp
		tmp1 = (struct w_to_w_ptr *)malloc(sizeof(struct w_to_w_ptr));
		tmp1->addr = addr;
		tmp1->dst = bp;
		tmp1->next = 0x00;

		if (w_to_w_first == 0) {	// we are first
			w_to_w_first = tmp1;
		} else {	// append
			struct w_to_w_ptr *tmp2 = w_to_w_first;
			while (tmp2->next != 0) {
				tmp2 = (struct w_to_w_ptr *) tmp2->next;
			}
			tmp2->next = (addr_size) tmp1;
		}

		// save eip
		tmp3 = (struct w_to_x_ptr *)malloc(sizeof(struct w_to_x_ptr));
		tmp3->addr = addr + 4;
		tmp3->dst = word;
		tmp3->next = 0x00;

		if (w_to_x_first == 0) {	// we are first
			w_to_x_first = tmp3;
		} else {	// append
			struct w_to_x_ptr *tmp4 = w_to_x_first;
			while (tmp4->next != 0) {
				tmp4 = (struct w_to_x_ptr *)tmp4->next;
			}
			tmp4->next = (addr_size) tmp3;
		}
	}
	if(verbose_flag)
		zprintf("\n");
	return 0;
}

/*
* Display possible function pointers
*/
int display_possible_fptrs(){
	int counter = 0;
	struct w_to_x_ptr *tmp4;

	zprintf("\n--[ Possibly valid function pointers:\n");
	tmp4 = w_to_x_first;
	while (tmp4 != 0) {

		if ((tmp4->valid)&&(tmp4->function_start||(!strict_mode))) {
#ifdef __x86_64__
				printf("0x%016llx --> 0x%016llx %s\n", tmp4->addr, tmp4->dst,
#else
				printf("0x%08x --> 0x%08x %s\n", tmp4->addr, tmp4->dst,
#endif
				       (tmp4->addr % 4) ? "(unalined)" : "");
			counter++;
		}
		tmp4 = (struct w_to_x_ptr *)tmp4->next;
	}

	zprintf("\n --> total : %d possible pointers\n", counter);
	return 0;
}

/*
* Find function pointers exploitable
* by truncation
*/
int find_trunc_targets(int destperm,addr_size inputptr, int aligned){
	int counter = 0;
	struct w_to_x_ptr *tmp4;

	zprintf("\n--[ Function pointers exploitable by %struncation with 0x%08x:\n",
		(aligned) ? "4 byte aligned " : "" ,inputptr);
	tmp4 = w_to_x_first;
	while (tmp4 != 0) {
		if ( ((tmp4->addr % 4)||(!aligned)) && (tmp4->hijack == 1)) {	// source ptr valid and unalined ?
			if(tmp4->addr % 4)
				tmp4->unaligned=1;
			counter+=checktrunc(tmp4,destperm,inputptr,0,aligned);	// lower truncation
			counter+=checktrunc(tmp4,destperm,inputptr,1,aligned);	// upper truncation
			tmp4->truncsploit=1;
		}
		tmp4 = (struct w_to_x_ptr *)tmp4->next;

	}

	zprintf("\n --> total : %d exploitable pointers\n\n", counter);
	return 0;
}

/*
* get permissions in human readable format
*/
int ptoh(int perms, char hperms[]){

	if (perms & 0x1) {
		sprintf(hperms, "%s%s", hperms, "X");
	}
	if (perms & 0x2) {
		sprintf(hperms, "%s%s", hperms, "R");
	}
	if (perms & 0x4) {
		sprintf(hperms, "%s%s", hperms, "W");
	}
	if (perms & 0x8) {
		sprintf(hperms, "%s%s", hperms, "S");
	}

	return 0;
}

/*
* If truncated using an arbitrary input ptr,
* is the resulting pointer pointing to a valid
* address mapped in a +W section ? in a +X section ?
*
* Note: if several truncations are possible
* given certain inputs, we consider all of
* them (provided correct destination perms).
*
* If the "aligned" flag is specified,
* we only consider the
* (at most) 1 possible 4b aligned truncation.
*
*/
int checktrunc(struct w_to_x_ptr *tmp, int destperm,addr_size inputptr,int direction,int aligned){
	int tmax;			// compute how many bytes will be truncated at max (0,1,2,3)
	int v;				// compute ptr destination after truncation
	int p;				// permission of resulting ptr
	int d;
	int counter=0;			// how many successfull truncations ?

	tmax = (aligned) ? 4 - (tmp->addr % 4) : 3;
	for(d=tmax;d>0;d--){
		if(!direction){	// lower truncation
			switch (d) {
				case 1:
					v = (tmp->dst & 0xffffff00) + (inputptr/0x1000000);
					break;
				case 2:
					v = (tmp->dst & 0xffff0000) + (inputptr/0x10000);
					break;
				case 3:
					v = (tmp->dst & 0xff000000) + (inputptr/0x100);
					break;
			}
		}else{		// upper truncation
			switch (d) {
				case 1:
					v = (tmp->dst & 0x00ffffff) + (inputptr & 0x000000ff)*0x1000000;
					break;
				case 2:
					v = (tmp->dst & 0x0000ffff) + (inputptr & 0x0000ffff)*0x10000;
					break;
				case 3:
					v = (tmp->dst & 0x000000ff) + (inputptr & 0x00ffffff)*0x100;
					break;
			}
		}

		p = ptr_to_perms(v);

		if ((v != tmp->dst)&&(p)&&(tmp->valid)&&(p&destperm)) {
		// Verify we are actually modifying the destination pointer
		// that the destination is mapped
		// that the original ptr is a function prologue
		// that the permissions requested on dest match
			char hperms[10];
			memset(hperms, 0x00, 10);
			ptoh(p, hperms);

			zprintf("At 0x%08x : 0x%08x will become 0x%08x"
				" (%s truncated by %d bits, dest perms:%s)\n",
				tmp->addr, tmp->dst, v,
				(direction == 1) ? "upper" : "lower",
				d*8, hperms);
			tmp->trunc = 1;
			counter++;
		}
		if(aligned){	// one possible truncation only
			break;
		}
	}
	return counter;
}

/*
* get permissions of a given address
*/
int ptr_to_perms(addr_size addr){
	struct any_ptr *new = (struct any_ptr *)malloc(sizeof(struct any_ptr));
	struct section *tmpsection = zfirst;

	memset(new, 0x00, sizeof(struct any_ptr));
	while (tmpsection != 0x00) {
		if ((tmpsection->init <= addr) && (tmpsection->end > addr)) {
			return tmpsection->perms;
		}
		tmpsection = tmpsection->next;
	}
	return 0;
}

/*
* get ASLR repeatability for a given address
*/
int ptr_to_aslr(addr_size addr){
	struct any_ptr *new = (struct any_ptr *)malloc(sizeof(struct any_ptr));
	struct section *tmpsection = zfirst;

	memset(new, 0x00, sizeof(struct any_ptr));
	while (tmpsection != 0x00) {
		if ((tmpsection->init <= addr) && (tmpsection->end > addr)) {
			return tmpsection->proba;
		}
		tmpsection = tmpsection->next;
	}
	return 0;
}

/*
* get ASLR most probable mapping for a given address
*/
int ptr_to_aslrval(addr_size addr){
	struct any_ptr *new = (struct any_ptr *)malloc(sizeof(struct any_ptr));
	struct section *tmpsection = zfirst;

	memset(new, 0x00, sizeof(struct any_ptr));
	while (tmpsection != 0x00) {
		if ((tmpsection->init <= addr) && (tmpsection->end > addr)) {
			return (tmpsection->probableval - tmpsection->init + addr);
		}
		tmpsection = tmpsection->next;
	}
	return 0;
}


/*
* Is a given address mapped ?
*/
int is_mapped(addr_size addr){

	struct section *tmpsection = zfirst;
	while (tmpsection != 0x00) {
		if ((tmpsection->init < addr) && (tmpsection->end > addr)) {
			return 1;
		}
		tmpsection = tmpsection->next;
	}
	return 0;
}

int parse_w_sections(int pid)
{
	struct section *tmpsection;
	char dev[50];
	int fd;

	memset(dev,0x00,50);
	sprintf(dev,"/proc/%d/mem",pid);
	fd=open64(dev,O_RDONLY|O_LARGEFILE);

	zprintf("\n--[ Listing writable sections:\n");

	tmpsection = zfirst;
	while (tmpsection != 0x00) {
		parse_section(fd, tmpsection->init,tmpsection->end, tmpsection->size, 1,tmpsection->name);
		tmpsection = tmpsection->next;
	}

	close(fd);
	return 0;
}

int parse_section(int fd, addr_size addr,addr_size end, int size, int perms,char *name){

	int num = 0;
	int count = 0;
	char *buf;
	char hperms[10];
	int newptr;

	// get permissions in human readable form
	memset(hperms, 0x00, 10);
	ptoh(ptr_to_perms(addr), hperms);

	if (((ptr_to_perms(addr)) & 4) == 0) {	// has to be +W 
		if(verbose_flag){
#ifdef __x86_64__
			zprintf(" <!> Section at 0x%016llx-0x%016llx (%s)\n",
#else
			zprintf(" <!> Section at 0x%08x-0x%08x (%s)\n",
#endif
			 addr,end, hperms);
		}
		return 0;
	} else {
#ifdef __x86_64__
		zprintf(" <*> Section at 0x%016llx-0x%016llx (%s) %s\n",
#else
		zprintf(" <*> Section at 0x%08x-0x%08x (%s) %s\n",
#endif
		 addr,end, hperms,strlen(name) ? name : "");
	}

	buf = (char *)malloc(size+4);
	memset(buf, 0x00, size+4);

	num = pread64(fd, buf, size,(unsigned long int)addr);
	if(num <=0){
		perror(" [!!] pread64");
#ifdef __x86_64__
		printf(" [!!] Section at 0x%016llx-0x%016llx (%s) %s\n",
#else
		printf(" [!!] Section at 0x%08x-0x%08x (%s) %s\n",
#endif
		 addr,end, hperms,strlen(name) ? name : "");

		exit(-1);
	}

	// parse section looking for pointers to sections with interresting perms
	for (count = 0; count < num; count += 1) {

	newptr=(buf[count]&0xff)+(buf[count+1]&0xff)*0x100+(buf[count+2]&0xff)*0x10000+(buf[count+3]&0xff)*0x1000000;

		// matching ptr with correct perms
		if (is_mapped(newptr)) {

 			if ((ptr_to_perms(newptr) & 1) != 0){
				w_to_x_add(addr + count, newptr);
			}
 			if ((!fptr_flag)&&((ptr_to_perms(newptr) & 2) != 0)){
				w_to_r_add(addr + count, newptr);
			}
 			if ((!fptr_flag)&&((ptr_to_perms(newptr) & 4) != 0)){
				w_to_w_add(addr + count, newptr);
			}
 			if ((!fptr_flag)&&((ptr_to_perms(newptr) & 8) != 0)){
				w_to_s_add(addr + count, newptr);
			}
		}
	}
	return 0;
}

/*
* add an element to linked list of function pointers
*/
int w_to_x_add(addr_size addr, addr_size ptr)
{
	struct w_to_x_ptr *tmp3;
	tmp3 = (struct w_to_x_ptr *)malloc(sizeof(struct w_to_x_ptr));
	tmp3->addr = addr;
	tmp3->dst = ptr;
	tmp3->next = 0x00;

	if (w_to_x_first == 0) {	// we are first
		w_to_x_first = tmp3;
	} else {		// append
		struct w_to_x_ptr *tmp4 = w_to_x_first;
		while (tmp4->next != 0) {
			tmp4 = (struct w_to_x_ptr *)tmp4->next;
		}
		tmp4->next = (addr_size)tmp3;
	}
	return 0;
}

/*
* add an element to linked list of rodata pointers
*/
int w_to_r_add(addr_size addr, addr_size ptr)
{
	struct w_to_r_ptr *tmp3;
	tmp3 = (struct w_to_r_ptr *)malloc(sizeof(struct w_to_r_ptr));
	tmp3->addr = addr;
	tmp3->dst = ptr;
	tmp3->next = 0x00;

	if (w_to_r_first == 0) {	// we are first
		w_to_r_first = tmp3;
	} else {		// append
		struct w_to_r_ptr *tmp4 = w_to_r_first;
		while (tmp4->next != 0) {
			tmp4 = (struct w_to_r_ptr *)tmp4->next;
		}
		tmp4->next = (addr_size)tmp3;
	}
	w_to_r_counter++;
	return 0;
}

/*
* add an element to linked list of data pointers
*/
int w_to_w_add(addr_size addr, addr_size ptr)
{
	struct w_to_w_ptr *tmp3;
	tmp3 = (struct w_to_w_ptr *)malloc(sizeof(struct w_to_w_ptr));
	tmp3->addr = addr;
	tmp3->dst = ptr;
	tmp3->next = 0x00;

	if (w_to_w_first == 0) {	// we are first
		w_to_w_first = tmp3;
	} else {		// append
		struct w_to_w_ptr *tmp4 = w_to_w_first;
		while (tmp4->next != 0) {
			tmp4 = (struct w_to_w_ptr *)tmp4->next;
		}
		tmp4->next = (addr_size)tmp3;
	}

	w_to_w_counter++;
	return 0;
}

/*
* add an element to linked list of shared sections pointers
*/
int w_to_s_add(addr_size addr, addr_size ptr)
{
	struct w_to_s_ptr *tmp3;
	tmp3 = (struct w_to_s_ptr *)malloc(sizeof(struct w_to_s_ptr));
	tmp3->addr = addr;
	tmp3->dst = ptr;
	tmp3->next = 0x00;

	if (w_to_s_first == 0) {	// we are first
		w_to_s_first = tmp3;
	} else {		// append
		struct w_to_s_ptr *tmp4 = w_to_s_first;
		while (tmp4->next != 0) {
			tmp4 = (struct w_to_s_ptr *)tmp4->next;
		}
		tmp4->next = (addr_size)tmp3;
	}
	w_to_s_counter++;
	return 0;
}

/*
* disassemble at a given address
*/
int disasm_size;

int disassemble(int pid, addr_size addr, char *line)
{
	char raw[40];
	DISASM MyDisasm;
	memset (&MyDisasm, 0, sizeof(DISASM));
#ifdef __x86_64__
	MyDisasm.Archi = 64; 
#else
	MyDisasm.Archi = 32; 
#endif

	// get 40b of data, starting at eip-20
	memset(raw, 0x00, 40);
	getdata(pid, addr, raw, 40);
	memset(line, 0x00, 400);

	MyDisasm.EIP = (addr_size)raw;

	disasm_size=Disasm(&MyDisasm);
	sprintf(line,"%s",MyDisasm.CompleteInstr);

	if (strlen(line) > 1) {
		//
	} else {
		zprintf("invalid pointer\n");
		return -2;
	}

	return 0;
}


/*
* Is the pointer pointing to a valid instruction ?
*
* Methodology: disasm from ptr, check if tmp->dst starts
* with a valid asm instruction,then possibly a 
* function prologue
*
*/
int checkptr(int pid, struct w_to_x_ptr *tmp)
{
	char raw[20];
	char line[400];

	memset(raw, 0x00, 20);
	memset(line, 0x00, 400);

	getdata(pid, (addr_size)tmp->dst, raw, 20);
	disassemble(pid,(addr_size)tmp->dst,line);

	if (strlen(line) > 1) {
			if(debug_flag){
#ifdef __x86_64__
				printf("0x%016llx: %s\n", tmp->dst, line);
#else
				printf("0x%08x: %s\n", tmp->dst, line);
#endif
			}
			// check destination is indeed +X
			if(ptr_to_perms(tmp->dst) & 2){
				tmp->valid = 1;
			}

#ifdef __x86_64__

			/* check if it actually points to the start
			 of a valid function prologue (push ebp):
			 55                      push   rbp
			 48 89 e5                mov    rbp,rsp
			*/
			if(!memcmp(raw,"\x55\x48\x89\xe5",4))
			{
#else
			/*
			 55                      push   ebp
			 89 e5                   mov    ebp,esp
			*/
			if(!memcmp(raw,"\x55\x89\xe5",3))
			{
#endif
				tmp->function_start=1;
				if(debug_flag){
					printf("^--> valid function prologue\n");
				}
			}else{
				tmp->function_start=0;
				if(debug_flag) {
					printf("^--> invalid function prologue\n");
				}
			}
			return 1;
	} else {
		if(verbose_flag)
			printf("not a function pointer ? not valid disassembly\n");
		tmp->valid = 0;
		return 0;
	}
	return 0;
}

int checkallptrs(int pid)
{
	struct w_to_x_ptr *tmp4;

	if(verbose_flag)
		zprintf("\n--[ Attempting to disassemble from all possible pointers\n");

	// walk linked list of pointers
	tmp4 = w_to_x_first;
	while (tmp4 != 0) {

		checkptr(pid, tmp4);
		tmp4 = (struct w_to_x_ptr *)tmp4->next;
	}

	return 0;
}

int setallbps(int pid)
{
	// walk linked list of pointers
	struct w_to_x_ptr *tmp4 = w_to_x_first;
	while (tmp4 != 0) {
		if ((tmp4->valid) && (tmp4->trunc)) {
			setbp(pid, tmp4);
		}
		tmp4 = (struct w_to_x_ptr *)tmp4->next;
	}

	return 0;
}

int setbp(int pid, struct w_to_x_ptr *tmp)
{

	/* int 0x80, int3 */
	char code[] = {0xcc};

	/* Copy instructions into backup variable */
	getdata(pid, (addr_size)tmp->dst, tmp->backup, 4);
	/* Put the breakpoint */
	putdata(pid, tmp->dst, code, 4);
	return 0;
}

int restorebp(int pid, int dst, struct user_regs_struct regz)
{

	int delta = 0;
	struct w_to_x_ptr *tmp4;
	//we can have a delta from 0 to 3 (size of instructions)
	for (delta = 0; delta < 4; delta++) {
		// search element in linked list with such destination
		tmp4 = w_to_x_first;
		while (tmp4 != 0) {
			if ((tmp4->dst == dst - delta) && (tmp4->valid)
			    && (tmp4->trunc)) {
				goto found;
			}
			tmp4 = (struct w_to_x_ptr *)tmp4->next;
		}
	}
	printf(" [!] Could not restore breakpoint\n");
	return -1;

found:
#ifdef __x86_64__
	printf(" --> ptr from 0x%016llx ? (delta=%d) --> 0x%016llx\n\n",
#else
	printf(" --> ptr from 0x%08x ? (delta=%d) --> 0x%08x\n\n",
#endif
	 tmp4->addr, delta, tmp4->dst);

	// restore bp
	putdata(pid, tmp4->dst, tmp4->backup, 4);

	// find eip
	regz.ip = tmp4->dst;
	ptrace(PTRACE_SETREGS, pid, NULL, &regz);
	return 0;
}

int restoreall(int pid)
{
	struct w_to_x_ptr *tmp4;
	tmp4 = w_to_x_first;
	while (tmp4 != 0) {

		if (tmp4->valid) {
			restbp(pid, tmp4);
		}
		tmp4 = (struct w_to_x_ptr *)tmp4->next;
	}
	printf(" [*] Breakpoints restored\n");
	return 0;
}

int restbp(int pid, struct w_to_x_ptr *tmp)
{
	// restore bp
	putdata(pid, tmp->dst, tmp->backup, 4);
	return 0;
}

/*
* Parse/display registers
*/
int display_regs(char *line, struct user_regs_struct regz)
{

#ifdef __x86_64__


	// 64b
	if (strstr(line, "rax")){
		zprintf(" rax=0x%016llx\n", regz.rax);
	}
	if (strstr(line, "rbx")){
		zprintf(" rbx=0x%016llx\n", regz.rbx);
	}
	if (strstr(line, "rcx")){
		zprintf(" rcx=0x%016llx\n", regz.rcx);
	}
	if (strstr(line, "rdx")){
		zprintf(" rdx=0x%016llx\n", regz.rdx);
	}
	if (strstr(line, "rsi")){
		zprintf(" rsi=0x%016llx\n", regz.rsi);
	}
	if (strstr(line, "rdi")){
		zprintf(" rdi=0x%016llx\n", regz.rdi);
	}
	if (strstr(line, "rsp")){
		zprintf(" rsp=0x%016llx\n", regz.rsp);
	}
	if (strstr(line, "rbp")){
		zprintf(" rbp=0x%016llx\n", regz.rbp);
	}

	if (strstr(line, "r8")){
		zprintf(" r8=0x%016llx\n", regz.r8);
	}
	if (strstr(line, "r9")){
		zprintf(" r9=0x%016llx\n", regz.r9);
	}
	if (strstr(line, "r10")){
		zprintf(" r10=0x%016llx\n", regz.r10);
	}
	if (strstr(line, "r11")){
		zprintf(" r11=0x%016llx\n", regz.r11);
	}
	if (strstr(line, "r12")){
		zprintf(" r12=0x%016llx\n", regz.r12);
	}
	if (strstr(line, "r13")){
		zprintf(" r13=0x%016llx\n", regz.r13);
	}
	if (strstr(line, "r14")){
		zprintf(" r14=0x%016llx\n", regz.r14);
	}
	if (strstr(line, "r15")){
		zprintf(" r15=0x%016llx\n", regz.r15);
	}

	// 32b
	if (strstr(line, "eax")){
		zprintf(" eax=0x%08x\n", regz.rax&0xffffffff);
	}
	if (strstr(line, "ebx")){
		zprintf(" ebx=0x%08x\n", regz.rbx&0xffffffff);
	}
	if (strstr(line, "ecx")){
		zprintf(" ecx=0x%08x\n", regz.rcx&0xffffffff);
	}
	if (strstr(line, "edx")){
		zprintf(" edx=0x%08x\n", regz.rdx&0xffffffff);
	}
	if (strstr(line, "esi")){
		zprintf(" esi=0x%08x\n", regz.rsi&0xffffffff);
	}
	if (strstr(line, "edi")){
		zprintf(" edi=0x%08x\n", regz.rdi&0xffffffff);
	}
	if (strstr(line, "esp")){
		zprintf(" esp=0x%08x\n", regz.rsp&0xffffffff);
	}
	if (strstr(line, "ebp")){
		zprintf(" ebp=0x%08x\n", regz.rbp&0xffffffff);
	}


#else
	if (strstr(line, "eax"))
		zprintf(" eax= %08x\n", (unsigned int)regz.eax);

	if (strstr(line, "ebx"))
		zprintf(" ebx= %08x\n", (unsigned int)regz.ebx);

	if (strstr(line, "ecx"))
		zprintf(" ecx= %08x\n", (unsigned int)regz.ecx);

	if (strstr(line, "edx"))
		zprintf(" edx= %08x\n", (unsigned int)regz.edx);

	if (strstr(line, "esi"))
		zprintf(" esi= %08x\n", (unsigned int)regz.esi);

	if (strstr(line, "edi"))
		zprintf(" edi= %08x\n", (unsigned int)regz.edi);

	if (strstr(line, "esp"))
		zprintf(" esp= %08x\n", (unsigned int)regz.esp);

	if (strstr(line, "ebp"))
		zprintf(" ebp= %08x\n", (unsigned int)regz.ebp);

#endif
	return 0;
}

/*
* log to file and display to screen routine
*/
int zprintf(const char *format, ...){
	va_list ap;
	int r;

	char *str= (char*)malloc(4096);
	if(!str){
		perror(" [!!] malloc");
		exit(-1);
	}

	memset(str,0x00,4096);
	va_start(ap, format);
	r=vsprintf(str, format, ap);
	va_end(ap);

	fprintf(reportz,"%s",str);
	sync();
	printf("%s",str);
	free(str);

	return r;
}


/*
* WE TRY TO BE AS FAULT TOLERANT AS POSSIBLE
*
* The biggest risk of failure is that we need
* to wait() and not waitpid() inside mk_fork()
* since we don't know the pid of the offspring
* yet (hence a race condition).
* We also want to deal with the possible
* (unwanted) children of our forked() processes.
*
* This routine also deals with zombies:
* it makes sure no more than X_XOMBIES
* are present at the same time by killing
* the parent process in case it reaches this
* number (this involves keeping a list of
* ancestors and calling mk_fork() a
* number of time. This is the best tradeoff
* between performance and number of zombies
* we could manage.
*
*/
#define X_ZOMBIES 10	// 10^10 possible offsprings...
			// that should fullfill any debugging need...

int ancestors[10]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
int usage_counter[10]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

// main wrapper
int mk_fork_wrapper(pid_t pid){
// the given pid is always the top parent
//(id est: the original debugged process)
	int i,k;

	alarm(0);
	if(ancestors[0]==0x00){	// not initialized yet
		k=pid;
		for(i=0;i<10;i++){
			// create forked process
			ancestors[i]=mk_fork_wrapper2(k);
			k=ancestors[i];
			// create process group
			if(mk_setpgid(k)){
				printf(" [!!] Creating group %u failed\n",k);
			}
			if(debug_flag)
				printf("ancestors[%d]:%d ok\n",i,k);
		}
	}
	if(debug_flag)
		printf("ancestors populated\n");

	for(i=9;i>=0;i--){
		if(usage_counter[i]<X_ZOMBIES){
			if(i==9){ // we are final node ?
				usage_counter[i]+=1;	// inc usage counter
				if(debug_flag)
					printf("usage_counter[%d]=%d\n",i,usage_counter[i]);
				return mk_fork_wrapper2(ancestors[i]);
			}
			// we need to kill some processes...
			for(k=i+1;k<=9;k++){
				/*
				* kill all the offsprings till counter is < X_ZOMBIES
				* then recreate pid and process group
				*/
				// kill process group
				kill_group(ancestors[k]);
				// kill parent process
				kill_pid(ancestors[k]);

				// respawn process
				ancestors[k]=mk_fork_wrapper2(ancestors[k-1]);
				// recreate process group
				if(mk_setpgid(ancestors[k])){
					printf(" [!!] Creating group %u failed\n",ancestors[k]);
				}
				if(debug_flag)
					printf("ancestors[%d]:%d ok,counter(-1)=%d\n",k,ancestors[k],usage_counter[k-1]);
				usage_counter[k]=0x00;	// reinit usage counter
			}

			usage_counter[i]+=1;	// inc usage counter
			return mk_fork_wrapper2(ancestors[9]);
		}
	}
	printf(" [!!] Spawned zillions of processes, dying...\n");
	exit(-3);
}

/*
* Fault tolerance...
*/
int mk_fork_wrapper2(pid_t pid){
	// attemp up to MAX_FAIL_TIMES times
	int i,t;
	for(i=0;i<MAX_FAIL_TIMES;i++){
		t=mk_fork(pid);
		if((t>0)&&(t!=pid)){
			return t;
		}
		usleep(1000);
	}
	fprintf(stderr," [!!] %u failed attemps to mk_fork()"
		"in a raw :(, exiting..\n",MAX_FAIL_TIMES);
	exit(-1);
}

/*
*
* force a process to fork()
*
* returns the pid of the offspring
*
*/
int mk_fork(pid_t pid){

	addr_size target_addr;
	struct	user_regs_struct regz;
	struct	user_regs_struct regs;
	struct	user_regs_struct regz_new;
	int status,ret;
	siginfo_t si;
	struct w_to_x_ptr *tmp4;
	int newpid;
	int fork_ok=0,offspring_ok=0;

	// already tracing calls to fork() ? 
	if(!tracing_forks_flag){
		if(init_tracefork(pid) < 0){
			perror(" [!!] mk_fork: ptrace (init)");
			exit(-1);
		}
	}

	/*
	* prepare child to perform a fork
	*/

	// save registers
	if(ptrace(PTRACE_GETREGS, pid,NULL, &regz)){
		printf(" [!!] Fatal error for process: %d\n",pid);
		perror(" [!!] mk_fork: ptrace (PTRACE_GETREGS)");
		exit(-1);
	}
	if(debug_flag){
#ifdef __x86_64__
		printf("saved rip=%016llx\n",(addr_size)regz.rip);
#else
		printf("saved eip=%08x\n",(addr_size)regz.eip);
#endif
	}

	memcpy(&regz_new,&regz,sizeof(regz));

	// find a place +X in memory
	tmp4 = w_to_x_first;
	target_addr=0;
	while (tmp4->next != 0) {
#ifdef __x86_64__
		if(tmp4->function_start){
#else
		if((tmp4->function_start)&&(tmp4->valid)){
#endif
			if(debug_flag)
				printf("Function prologue: %s\nValid (strict) compatible: %s\n", (tmp4->function_start ? "yes" : "no"), (tmp4->valid ? "yes" : "no"));
			// valid function prologue in X section ? good enough for us :)
			target_addr= (addr_size)tmp4->dst;
			break;
		}
		tmp4 = (void *)tmp4->next;
	}

	if(!target_addr){
		printf(" [!!] Didn't find a place to inject shellcode !! // mk_fork\n");
		exit(-1);
	}

	// backup content at addr
	getdata(pid, (addr_size)target_addr, backup_buff, 200);
	if(debug_flag){
		printf(" -->> backed up original bytes at 0x%08x\n",(int)target_addr);
		hexdump(backup_buff,20);
	}

	/*
	* The first time we are called : use sigaction in the forked
	* process to ignore SIGCHLD // Zombie reaper trick
	*/
	if(first_fork){
		first_fork=0;

		// replace with sigaction stub
		write_data(pid,target_addr,sigaction_stub,180);

		// execute it
		regz_new.ip=(addr_size)target_addr+2;	// kernel bug ! thx @ #busticati :)

		if(ptrace(PTRACE_SETREGS, pid,NULL, &regz_new)){
			perror(" [!!] mk_fork: ptrace (PTRACE_SETREGS)");
		}

		// continue till SIGTRAP
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		waitpid(pid,&status,0);
		ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
		if(debug_flag){
			printf("Received signal from tracee (while sigaction shellcode...)\n");
			printf("signo: %i errno: %i code: %i\n", si.si_signo, si.si_errno,
			    si.si_code);
		}
	}

	// replace with fork_stub shellcode
	write_data(pid,target_addr,fork_stub,10);

	// execute fork_stub
	regz_new.ip=(addr_size)target_addr+2;	// kernel bug ! thx @ #busticati :)
	if(ptrace(PTRACE_SETREGS, pid,NULL, &regz_new)){
		perror(" [!!] mk_fork: ptrace (PTRACE_SETREGS)");
	}
	if(debug_flag){
		printf(" -->> executing fork stub at new ip=%p (%d)\n",
		(void *)regz_new.ip,ptr_to_perms(target_addr));
	}

	/* 
	* Continue ptracing untill we get a new offspring
	*/
	newpid=0;
	while(!newpid){
		memset(&si, 0, sizeof(siginfo_t));

		ptrace(PTRACE_GETREGS, pid,NULL, &regs);
		ptrace(PTRACE_SETREGS, pid,NULL, &regs);

		ptrace(PTRACE_CONT, pid, NULL, NULL);
		ret=waitpid(pid,&status,0);

		if (ret == pid && WIFSTOPPED (status)&& status >> 16 == PTRACE_EVENT_FORK){
			ret = ptrace (PTRACE_GETEVENTMSG, pid, 0, &newpid);
			if (ret == 0 && newpid != 0){
				if(verbose_flag)
					printf("newpid:%u\n",newpid);
			} else{
				fprintf(stderr," [!!] no new pid ?\n");
				newpid=0;
			}
		}else{
			ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
			if(si.si_signo == 5){ // parent ?
				if(verbose_flag)
					printf(" -->> debugged process survived fork()\n");
			}else if(si.si_signo == 11){
				if(verbose_flag)
					fprintf(stderr," [!!] Received signal 11 !! mk_fork() failed...");
				goto try_to_live;
			}else{
				if(verbose_flag){
					printf("Received signal from tracee\n");
					printf("signo: %i errno: %i code: %i\n", si.si_signo, si.si_errno,
				            si.si_code);
				}
			}
		}
		usleep(1);
	}

try_to_live:

	/*
	* Clean up the mess
	*/
	if(verbose_flag)
		printf(" -->> Restoring both processes:\n");

	// clear signals
	if(verbose_flag)
		printf("  ** clearing signals\n");
	memset(&si, 0, sizeof(siginfo_t));
	ptrace(PTRACE_SETSIGINFO, pid, NULL, &si);
	ptrace(PTRACE_SETSIGINFO, newpid, NULL, &si);

	// restore data
	if(verbose_flag)
		printf("  ** restoring saved bytes\n");
	write_data(pid,target_addr,backup_buff,200);
	write_data(newpid,target_addr,backup_buff,200);

	// restore registers
	if(verbose_flag){
		printf("  ** restoring ip=%p\n",(void *)regz.ip);
	}

	if((ptrace(PTRACE_SETREGS, pid, NULL, &regz))||
	  (ptrace(PTRACE_SETREGS, newpid, NULL, &regz))){
		// avoid unecessary zombies:
		if(newpid!=pid){
			kill_pid(newpid);
		}
		return -1;
	}

	return newpid;
}


/*
* mk_setpgid() : force a process to create a process group
*/
int mk_setpgid(int pid){

	addr_size target_addr;
	struct	user_regs_struct regz;
	struct	user_regs_struct regz_new;
	int status;
	siginfo_t si;
	struct w_to_x_ptr *tmp4;

	// save registers
	if(ptrace(PTRACE_GETREGS, pid,NULL, &regz)){
		printf(" [!!] Error for process: %d\n",pid);
		perror(" [!!] mk_setpgid: ptrace (PTRACE_GETREGS)");
		return -1;
	}
	memcpy(&regz_new,&regz,sizeof(regz));

	// find a place +X in memory
	tmp4 = w_to_x_first;
	target_addr=0;
	while (tmp4->next != 0) {
		if((tmp4->function_start)&&(tmp4->valid)){
		// valid function prologue in X section ? good enough for us :)
			target_addr= tmp4->dst;
			break;
		}
		tmp4 = (void *)tmp4->next;
	}

	if(!target_addr){
		printf(" [!!] Didn't find a place to inject setpgid() shellcode !! // mk_setpgid\n");
		return -1;
	}

	// backup content at addr
	getdata(pid, target_addr, backup_buff, 20);
	// replace with setpgid_stub shellcode
	write_data(pid,target_addr,setpgid_stub,17);
	// execute setpgid_stub
	regz_new.ip=target_addr+2;	// kernel bug ! thx @ #busticati :)
	if(ptrace(PTRACE_SETREGS, pid,NULL, &regz_new)){
		perror(" [!!] mk_setpgid: ptrace (PTRACE_SETREGS)");
		return -1;
	}

	ptrace(PTRACE_CONT, pid, NULL, NULL);
	waitpid(pid,&status,P_ALL); // wait our pid

	// clear signals
	memset(&si, 0, sizeof(siginfo_t));
	ptrace(PTRACE_SETSIGINFO, pid, NULL, &si);
	// restore data
	write_data(pid,target_addr,backup_buff,20);
	// restore registers
	if(ptrace(PTRACE_SETREGS, pid, NULL, &regz)){
		perror(" [!!] mk_setpgid(): ptrace (PTRACE_SETREGS 2)");
		return -1;
	}

	return 0;
}


/*
* mk_mmap() : force a process to create a new memory mapping,
* then produce a remarkable mapping:
0x01010101
0x02020202
...
0xfefefefe

then fill the rest with 0xffffffff up to 1 page

*/
int mk_mmap(int pid){

	addr_size target_addr;
	struct	user_regs_struct regz;
	struct	user_regs_struct regs;
	struct	user_regs_struct regz_new;
	int status;
	siginfo_t si;
	struct w_to_x_ptr *tmp4;
	addr_size new_mapping;
	int i;
	int j;
	char canari_data[4];

	// save registers
	if(ptrace(PTRACE_GETREGS, pid,NULL, &regz)){
		printf(" [!!] Error for process: %d\n",pid);
		perror(" [!!] mk_setpgid: ptrace (PTRACE_GETREGS)");
		return -1;
	}
	memcpy(&regz_new,&regz,sizeof(regz));

	// find a place +X in memory
	tmp4 = w_to_x_first;
	target_addr=0;
	while (tmp4->next != 0) {
		if((tmp4->function_start)&&(tmp4->valid)){
		// valid function prologue in X section ? good enough for us :)
			target_addr= tmp4->dst;
			break;
		}
		tmp4 = (void *) tmp4->next;
	}

	if(!target_addr){
		printf(" [!!] Didn't find a place to inject setpgid() shellcode !! // mk_mmap\n");
		return -1;
	}

	// backup content at addr
	getdata(pid, target_addr, backup_buff, 40);
	// replace with mmap_stub shellcode
	write_data(pid,target_addr,mmap_stub,40);
	// execute mmap_stub
	regz_new.ip=target_addr+2;	// kernel bug ! thx @ #busticati :)
	if(ptrace(PTRACE_SETREGS, pid,NULL, &regz_new)){
		perror(" [!!] mk_setpgid: ptrace (PTRACE_SETREGS)");
		return -1;
	}

	ptrace(PTRACE_CONT, pid, NULL, NULL);
	waitpid(pid,&status,P_ALL); // wait our pid

	// pick up eax : it is the address of the created mapping !!
	if(ptrace(PTRACE_GETREGS, pid,NULL, &regs)){
		printf(" [!!] Error for process: %d\n",pid);
		perror(" [!!] mk_setpgid: ptrace (PTRACE_GETREGS 2)");
		return -1;
	}
#ifdef __x86_64__
	new_mapping=regs.rax;
#else
	new_mapping=regs.eax;
#endif
	// clear signals
	memset(&si, 0, sizeof(siginfo_t));
	ptrace(PTRACE_SETSIGINFO, pid, NULL, &si);
	// restore data
	write_data(pid,target_addr,backup_buff,40);
	// restore registers
	if(ptrace(PTRACE_SETREGS, pid, NULL, &regz)){
		perror(" [!!] mk_setpgid(): ptrace (PTRACE_SETREGS 2)");
		return -1;
	}

	// create remarkable mapping starting from eax (new mapping):
	j=0;
	
	for(i=1;i<0xff;i++){
		sprintf(canari_data,"%c%c%c%c",i,i,i,i);
		if(debug_flag){
			hexdump(canari_data,4);
		}
		write_data(pid,(addr_size)(new_mapping+j*4),canari_data,4);
		j++;
	}
	i=0xff;
	sprintf(canari_data,"%c%c%c%c",i,i,i,i);
	while(j<1024){	// fill up to 1 page (size of new mapping)
		write_data(pid,(addr_size)(new_mapping+j*4),canari_data,4);
		j++;
	}
	// return address of new mapping
	return new_mapping;
}


/*
* set the apropriate ptrace options to follow calls to fork()
*/ 
int init_tracefork(pid_t pid){
	int ret;
	ret = ptrace (PTRACE_SETOPTIONS, pid, 0,
                PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORKDONE);

	// set tracing flag (init only needs to be called once)
	tracing_forks_flag=1;
	return ret;
}

int trace_to_segfault(int pid){
	siginfo_t si;

	memset(&si, 0, sizeof(siginfo_t));

	printf(" [*] Waiting for a Segfault...\n\n");

	while(si.si_signo != 11){
		// continue untill we get a signal
		ptrace(PTRACE_CONT, pid, NULL, NULL);
		wait(NULL);
		printf("Received signal from process:\n");
		ptrace(PTRACE_GETSIGINFO, pid, NULL, &si);
		printf("signo: %i errno: %i code: %i\n", si.si_signo, si.si_errno,
	            si.si_code);

		last_signal=11;
	}
	return 0;
}


