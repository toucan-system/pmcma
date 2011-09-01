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

/*
* This is the main routine of
* the application
*/
int pwnage_analysis(int pid){

	/*
	* Perform main analysis
	*/
	analyze(pid);

	if(interactive_flag){	// prompt for action
		while(1)
			prompt_user(pid);
	} else {		// automated analysis

//		if(leak_flag){
//			memleak_analysis(pid);
//			exit(0);
//		}

		/*
		* detect if crash happens in a loop, or what is next crash address
		*/
		detect_next_crash(pid);

		/*
		* display info about POTENTIAL function ptrs
		*/
		if(verbose_flag)
			display_possible_fptrs();

//
// General rule is : go from the less costly (smart heuristics)
// to the most costly and exhaustive
//
//

		/*
		* First attempt to overwrite possible function pointers
		* pointing to valid prologues
		*/

		// validate found ptrs
		validate_ptrs(pid);

		// find targets to truncation, no necessarily 4b aligned
		find_trunc_targets(4,0x41424344,0);	// destination :+W section

		// find targets to truncation, 4b aligned
		find_trunc_targets(15,0x00000000,1);	// destination: anything mapped

		/*
		* Now use relaxed mode, search for function ptrs even if the
		* destination address isn't a standard function prologue
		*/
		strict_mode=0;	// switch to relaxed mode
		validate_ptrs(pid);

		// find targets to truncation, no necessarily 4b aligned
		find_trunc_targets(4,0x41424344,0);	// destination :+W section

		// find targets to truncation, 4b aligned
		find_trunc_targets(15,0x00000000,1);	// destination: anything mapped

		/*
		* Search pointers to structures containing function pointers
		*/
		validate_struct_ptrs(pid);

		/*
		* Attempt to overwrite anything in +W sections with no ASLR
		* this will in particular parse the GOT (if not compiled with full RELRO and no PIE)
		*/
		validate_all_w(pid,0);

		/*
		* Attempt to overwrite anything in +W sections even if randomized
		* LAST RESORT !!! (super costly)
		*/
		validate_all_w(pid,1);

		/*
		* Conclude...
		*/


		/*
		* Read operations...
		*/


		/*
		* exploit
		*/
//		if(exploit_flag){
//			exploit(pid);
//		}



	}
	// kill main debugged process
	kill_pid(pid);
	return 0;
}


int prompt_user(int pid){

// FIXME

	return 0;
}
