#include <stdlib.h>

int foo(char* arg) {
char text[1024];
int test_val = -72;

strcpy(text,arg);
printf(text);
printf("\n");
printf("[*] test_val @ 0x%08x = %d 0x%08x\n", &test_val, test_val, test_val);

}

int main(int argc, char *argv[]) {
static int test_val = -72;
if(argc < 2) {
printf("Wrong usage");
exit(0);
}
foo(argv[1]);
}
