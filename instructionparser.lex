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
* Trivial x86 intel syntax instruction parser
*
* determine if it is a read,
* write, or unkown operation
*
* Jonathan Brossard // endrazine@gmail.com
*/

%{
#include <stdio.h>

extern int read_op;
extern int write_op;
extern FILE *stdout;

%}


memmove "stosb"|"stosd"|"stosw"|"lodsb"|"lodsd"|"lodsw"
move "cmova"|"cmovc"|"cmovg"|"cmovng"|"cmovns"|"cmovo"|"cmovpe"|"cmovs"|"fcmovb"|"fcmovbe"|"fcmove"|"fcmovnb"|"fcmovnbe"|"fcmovne"|"fcmovnu"|"fcmovu"|"mov"|"movaps"|"movhps"|"movlhps"|"movlps"|"movnti"|"movntps"|"movq"|"movsb"|"movsd"|"movsw"|"movsx"|"movups"|"movzx"|"pmovmskb"|"lea"

ands "and"|"andnps"|"andps"|"pand"|"pandn"
xors "pxor"|"xor"
otherlogics "neg"|"nop"|"not"|"or"
logic {ands}|{xors}|{otherlogics}

adds "add"|"adc"|"addps"|"fadd"|"faddp"|"fiadd"|"paddb"|"paddd"|"paddq"|"paddsb"|"paddsw"|"paddusb"|"paddw"|"pmaddwd"|"vpaddd"|"vpaddw"|"xadd"
subs "fisub"|"fisubr"|"fsub"|"fsubp"|"fsubr"|"fsubrp"|"psubb"|"psubd"|"psubq"|"psubsb"|"psubsw"|"psubusb"|"psubusw"|"psubw"|"sub"|"subps"
muls "fimul"|"fmul"|"fmulp"|"imul"|"mul"|"pmulhuw"|"pmulhw"|"pmullw"|"pmuludq"
divs "div"|"divps"|"fdiv"|"fdivp"|"fdivr"|"fdivrp"|"fidiv"|"fidivr"|"idiv"
otherarithmetics "inc"|"dec"|"shl"|"shld"|"shr"|"shrd"|"rol"|"ror"|"sar"
arithmetic {adds}|{subs}|{muls}|{divs}|{otherarithmetics}

write {memmove}|{move}|{arithmetic}|{logic}

emptykeyword " "|"byte"|"ptr"|"word"|"dword"|"qword"

space [\ \t]
newline "\n"
any [a-z0-9A-Z\t\ \+\-\*]

%%


{write}{space}*{emptykeyword}\[{any}*\]\,{any}* { // write operation
	write_op=1;
} ; BEGIN(INITIAL);

{any}*{space}*{any}*\,{any}*\[{any}*\] { // read operation
	read_op=1;
} ; BEGIN(INITIAL);


%%

int scan_instruction(char *data) {
	YY_BUFFER_STATE s;

	// reset flags
	read_op=0;
	write_op=0;

	// hijack stdout
	FILE *back=stdout;
	stdout=fopen("/dev/null","w");

	// scan the input
	s = yy_scan_string(data);
	yylex();
	yy_delete_buffer(s);

	// restore stdout
	stdout=back;
	return 0;
}


