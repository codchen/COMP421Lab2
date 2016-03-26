#include <stdio.h>
#include <comp421/yalnix.h>

void
recurse(char *who, int i)
{
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

    printf("FORK2> This program is a test mainly of Fork\n");
    printf("FORK2> BEFORE Fork(): If nothing else is printed, Fork fails \n");
    printf("FORK2> You should see lines from parent and child below:\n");

    
    if ((pid = Fork()) == 0)
    {
	printf("CHILD\n");
	recurse("child", 20);
    }
    else
    {
	printf("PARENT: child pid = %d\n", pid);
	recurse("parent", 20);
    }

    printf("FORK2 done.\n");
    Exit(0);
}
