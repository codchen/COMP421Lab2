#include <stdio.h>
#include <comp421/yalnix.h>

void
recurse(char *who, int i)
{
    printf("%s %d\n", who, i);
    Delay(1);
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

    printf("FORK2> This program is a test of scheduling\n");
    printf("FORK2> BEFORE Fork(): If nothing else is printed, Fork fails \n");
    printf("FORK2> You should see lines from parent and child\n");
    printf("FORK2> interleaving: if not interleaved, and Pause\n");
    printf("FORK2> is being called, the scheduling is giving\n");
    printf("FORK2> Idle more priority!!\n");
    printf("FORK2> If not interleraved and no Pause, a more\n");
    printf("FORK2> seriour problem with scheduling!!\n");

    
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
