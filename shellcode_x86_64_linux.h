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
00000000  6631C0            xor eax,eax
00000003  B002              mov al,0x2
00000005  CD80              int 0x80
*/
char fork_stub[]="\x90\x66\x31\xc0\xb0\x02\xcd\x80\xcc\xcc";

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
        pop ecx
        add ecx,0x18    ; delta to sigaction structure

        xor eax,eax
        mov al,0x43     ; sigaction
        mov ebx,0x11    ; SIGCHILD
        xor edx,edx     ; 0x00
        int 0x80

        db 0xcc, 0xcc,0xcc,0xcc

; struct sigaction sa = {.sa_handler = SIG_IGN};
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

*/
char sigaction_stub[]="\x90\x90\x90\x90\xe8\x00\x00\x00\x00\x59\x81\xc1\x18\x00\x00\x00"
		"\x31\xc0\xb0\x43\xbb\x11\x00\x00\x00\x31\xd2\xcd\x80\xcc\xcc\xcc\xcc\x01"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
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
	mov eax,0x39	; setpgid
	xor ebx,ebx
	xor ecx,ecx
	int 0x80

	db 0xcc, 0xcc
*/
char setpgid_stub[]="\x90\x90\x90\x90\xb8\x39\x00\x00\x00\x31\xdb\x31\xc9\xcd\x80\xcc\xcc";


/*
*
* old_mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, 0, 0) shellcode:
*

_start:
	nop
	nop
	nop
	nop

	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	xor esi, esi
	xor edi, edi

	mov bx, 0x1000		; 1 page
	mov cl, 0x3		; PROT_READ|PROT_WRITE
	mov dl, 0x21		; MAP_SHARED|MAP_ANON

	push eax
	push eax
	push edx
	push ecx
	push ebx
	push eax

	mov ebx, esp
	mov al, 0x5a		; sys_mmap
	int 0x80

	; eax contains address of new mapping

	db 0xcc, 0xcc, 0xcc, 0xcc
*/

char mmap_stub[]="\x90\x90\x90\x90\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x31\xff\x66\xbb\x00\x10\xb1\x03\xb2\x21\x50\x50\x52\x51\x53\x50\x89\xe3\xb0\x5a\xcd\x80\xcc\xcc\xcc\xcc";


char mmap_exec_stub[]="\x90\x90\x90\x90\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x31\xff\x66\xbb\x00\x10\xb1\x05\xb2\x21\x50\x50\x52\x51\x53\x50\x89\xe3\xb0\x5a\xcd\x80\xcc\xcc\xcc\xcc";

