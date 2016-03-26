#include <stdio.h>
#include <stdlib.h>
#include <comp421/yalnix.h>

void
recurse(char *who, int i)
{
    char waste[1024];	/* use up stack space in the recursion */
    char *mem = (char *)malloc(2048); /* use up heap space */
    int j;

    printf("mem %p\n", mem);

    for (j = 0; j < 1024; j++) 
	waste[j] = 'a';

    Delay(1);

    printf("%s %d\n", who, i);
    if (i == 0)
    {
	printf("Done with recursion\n");
	return;
    }
    else
	recurse(who, i - 1);
}

int
main(int argc, char **argv)
{
    int pid;

    setbuf(stdout, NULL);

    printf("BEFORE\n");

    if ((pid = Fork()) == 0)
    {
	printf("CHILD\n");
	recurse("child", 33);
    }
    else
    {
	printf("PARENT: child pid = %d\n", pid);
	recurse("parent", 33);
    }

    Exit(0);
}
