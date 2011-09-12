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

/*
* Note on shellcode stubs : they don't need to be 0x00 free :
* we introduce them using ptrace. They need to be
* position independant though...
*/

/* Note on x86_64, order of registers for system calls is rdi,
rsi, rdx, r10, r8 and r9 */

/*
forking shellcode:
_start:
	xor rax,rax
	mov al,0x39
	syscall
	db 0xcc,0xcc,0xcc,0xcc
*/

char fork_stub[]="\x90\x48\x31\xc0\xb0\x39\x0f\x05\xcc\xcc\xcc\xcc";

/*
* Sigaction shellcode: // Zombie reaper
* struct sigaction sa = {.sa_handler = SIG_IGN}; 
* sigaction(SIGCHLD, &sa, NULL);

_start:
	nop
	nop
	nop
	nop
	call fake
fake:
	pop rsi
	add rsi,0x2c	 ; delta to our int* buffer

	mov rax,0xd	 
	mov rdi,0x11
	xor rdx,rdx
	mov r10,0x8

	syscall

	db 0xcc, 0xcc,0xcc,0xcc

	db 01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
	db 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00

*/
char sigaction_stub[]=  "\x90\x90\x90\x90\xe8\x00\x00\x00\x00\x5e\x48\x83\xc6\x2c\x48\xb8"
			"\x0d\x00\x00\x00\x00\x00\x00\x00\x48\xbf\x11\x00\x00\x00\x00\x00"
			"\x00\x00\x48\x31\xd2\x49\xba\x08\x00\x00\x00\x00\x00\x00\x00\x0f"
			"\x05\xcc\xcc\xcc\xcc\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
/*
*
* setpgid(0,0); shellcode
*
_start:
	nop
	nop
	nop
	nop
	xor rax,rax
	mov al,0x6d	; setpgid
	xor rdi,rdi
	xor rsi,rsi
	syscall

	db 0xcc, 0xcc
*/
char setpgid_stub[]="\x90\x90\x90\x90\x48\x31\xc0\xb0\x6d\x48\x31\xff\x48\x31\xf6\x0f\x05\xcc\xcc";


/*
*
* old_mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0) shellcode:
*

_start:
	nop
	nop
	nop
	nop

	xor r9,r9 
	xor r8,r8 
	mov r10, 0x21		; MAP_SHARED|MAP_ANON
	mov rdx, 0x5		; PROT_READ|PROT_WRITE
	mov rsi, 0x1000		; 1 page
	xor rdi,rdi		
		
	mov al, 0x9		; sys_mmap
	syscall

	; rax contains address of new mapping

	db 0xcc, 0xcc, 0xcc, 0xcc

*/

char mmap_stub[]=       "\x90\x90\x90\x90\x4d\x31\xc9\x4d\x31\xc0\x49\xba\x21\x00\x00\x00"
			"\x00\x00\x00\x00\x48\xba\x03\x00\x00\x00\x00\x00\x00\x00\x48\xbe"
			"\x00\x10\x00\x00\x00\x00\x00\x00\x48\x31\xff\xb0\x09\x0f\x05\xcc"
			"\xcc\xcc\xcc";


char mmap_exec_stub[]="\x90\x90\x90\x90\x4d\x31\xc9\x4d\x31\xc0\x49\xba\x21\x00\x00\x00\x00\x00\x00\x00\x48\xba\x05\x00\x00\x00\x00\x00\x00\x00\x48\xbe\x00\x10\x00\x00\x00\x00\x00\x00\x48\x31\xff\xb0\x09\x0f\x05\xcc\xcc\xcc\xcc";

