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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#include "beaengine/BeaEngine.h"
#define BEA_ENGINE_STATIC  /* specify the usage of a static version of BeaEngine */
#define BEA_USE_STDCALL    /* specify the usage of a stdcall version of BeaEngine */


/*
 * permOfFile - return the file permissions in an "ls"-like string.
 */
char *permOfFile(mode_t mode)
{
    int i;
    char *p;
    static char perms[10];

    p = perms;
    strcpy(perms, "---------");

    /*
     * The permission bits are three sets of three
     * bits: user read/write/exec, group read/write/exec,
     * other read/write/exec.  We deal with each set
     * of three bits in one pass through the loop.
     */
    for (i=0; i < 3; i++) {
        if (mode & (__S_IREAD >> i*3))
            *p = 'r';
        p++;

        if (mode & (__S_IWRITE >> i*3))
            *p = 'w';
        p++;

        if (mode & (__S_IEXEC >> i*3))
            *p = 'x';
        p++;
    }

    /*
     * Put special codes in for set-user-id, set-group-id,
     * and the sticky bit.  (This part is incomplete; "ls"
     * uses some other letters as well for cases such as
     * set-user-id bit without execute bit, and so forth.)
     */
    if ((mode & S_ISUID) != 0)
        perms[2] = 's';

    if ((mode & S_ISGID) != 0)
        perms[5] = 's';

    if ((mode & S_ISVTX) != 0)
        perms[8] = 't';

    return(perms);
}

int dump_maps_file_permissions(int pid) {
	FILE *maps;
	FILE *permissions;
	char maps_path[255];
	char line[1024];
	char *map_path;
	struct stat *buf = malloc(sizeof(struct stat));
	
	snprintf(maps_path, 255, "/proc/%d/maps", pid);

	maps = fopen(maps_path, "r");	
	if (maps==NULL){
		zprintf("Error reading maps permissions");
		return 1;
	}

	permissions = fopen("permissions.txt", "w");
	if (permissions==NULL){
		zprintf("Error opening permissions file");
		return 1;
	}

	while ( fgets ( line, sizeof line, maps ) != NULL ) {
		map_path = strstr(line, "/");	
           	if (map_path != NULL) {               
           	    stat(map_path, buf);
		    fprintf(permissions, "%s %d %d %d %ld %s", 
			permOfFile(buf->st_mode), 
			(int)buf->st_nlink, 
			(int)buf->st_uid, 
			(int)buf->st_gid, 
			(long)buf->st_size, 
			map_path);
        	}
	}

	fclose(maps);
	fclose(permissions);

	return 0;
}

/*
* Extract/dump some informations about
* the running process
*
* Note: FIXME, this routine is ugly++ ;(
*
*/

int reporting(int pid){

	// create directory
	char dname[200];
	memset(dname,0x00,200);
	sprintf(dname,"./report-%d",pid);
	mkdir(dname,0711);
	chdir(dname);

	// get core file
	exec_cmd("gcore -o ./corefile %d >/dev/null 2>&1",pid);	// won't work if we are already attached using ptrace...

	// copy map
	exec_cmd("cp /proc/%d/maps ./",pid);

	// dump file permissions associated to mappings
	dump_maps_file_permissions(pid);

	// Open report file
	reportz=fopen(REPORTDIR"/analysis.txt","w+");
	if(reportz == 0){
		perror(" [!!] fopen");
		exit(-1);
	}
	return 0;
}



int print_cmd_line(int pid){

	char mypath[100];
	char data[1024];
	unsigned int n,i;
	int fd;

	memset(data,0x00,1024);
	memset(mypath,0x00,100);

	sprintf(mypath,"/proc/%d/cmdline",pid);
	fd=open(mypath,O_RDONLY);

	n=read(fd,data,1024);
	if(n<=0){
		perror(" [!!] read");
		exit(-1);
	}
	close(fd);

	// fix 0x00...
	for(i=0;i<n;i++){
		if(data[i]==0x00){
			data[i]=0x20;
		}
	}
	zprintf("--[ Command line:\n%s\n\n",data);
	return 0;
}

int check_uids(int pid){

	char mypath[100];
	char data[1024];
	unsigned int n;
	char *startuids;
	int fd;

	sprintf(mypath,"/proc/%d/status",pid);
	fd=open(mypath,O_RDONLY);

	n=read(fd,data,1024);
	if(n<=0){
		perror(" [!!] read");
		exit(-1);
	}
	close(fd);

	zprintf("\n--[ User/Group ids:\n");
	startuids=strstr(data,"Uid:");
	sscanf(startuids+5,"%d\t%d\t%d\t%d\n",
		&uid, &euid, &saved_uid, &fsuid);
	zprintf("uid=%d euid=%d saved_uid=%d fsuid=%d\n",
		uid, euid, saved_uid, fsuid);
	startuids=strstr(data,"Gid:");
	sscanf(startuids+5,"%d\t%d\t%d\t%d\n",
		&gid, &egid, &saved_gid, &fsgid);
	zprintf("gid=%d egid=%d saved_gid=%d fsgid=%d\n",
		gid, egid, saved_gid, fsgid);

	return 0;
}

