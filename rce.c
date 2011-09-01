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
* Execute an external command
*/
int exec_cmd(char *command,int pid){
	char cmd[1024];
	FILE *output;
	int result;

	memset(cmd,0x00,1024);
	snprintf(cmd,1024,command,pid);
	output=popen(cmd, "r");
	fscanf(output,"%d",&result);
	pclose(output);
	return result;
}

/*
* Execute an external command, return stdout
* Don't forget to close after use
*/
FILE* exec_cmd_stdout(char *command,int pid){
	char cmd[1024];
	FILE *output;

	memset(cmd,0x00,1024);
	sprintf(cmd,command,pid);
	output=popen(cmd, "r");
	return output;
}


/*
* Check we have been installed properly,
* meaning that all the external tools
* we may need are present.
* We need the following tools on our path:
*
* [tool]    [package]
* readelf : binutils
* execstack : execstack
* gcore : gdb
*/
int check_install(){
	char *app_name[]={"readelf","gcore","execstack"};
	char cmd[1024];
	int result;
	FILE *output;
	int i;

	for(i=0;i<3;i++){
		memset(cmd,0x00,1024);
		sprintf(cmd,"which %s 2>/dev/null |wc -l",app_name[i]);
		output=popen(cmd, "r");
		fscanf(output,"%d",&result);
		pclose(output);
		if(!result){
			printf(" [!] No binary %s found in your path !!\n"
			"Please install it before proceeding\n",app_name[i]);
			return 1;
		} 
	}
	return 0;
}
